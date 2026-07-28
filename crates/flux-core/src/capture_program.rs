use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha256};

use crate::address_bypass::{AddressHostFamilySelection, AddressHostSetPlan};
use crate::network_inventory::{InterfaceName, NetworkEpoch, NetworkInventorySnapshotId};
use crate::network_route::NetworkAddressFamily;

/// Schema version for the backend-neutral Capture Program.
pub const CAPTURE_PROGRAM_SCHEMA_VERSION: u16 = 1;
/// Compiled maximum for normalized destination prefixes in each address family.
pub const MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY: usize = 65_536;
/// Absolute raw-input ceiling for configurable destination prefixes across both families.
pub const MAX_CAPTURE_POLICY_PREFIX_INPUTS: usize = MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY * 2;
/// Compiled maximum for resolved application UIDs.
pub const MAX_CAPTURE_POLICY_UIDS: usize = 20_000;
/// Compiled maximum for configured interface selectors.
pub const MAX_CAPTURE_INTERFACE_SELECTORS: usize = 128;
/// Compiled maximum for inventory-derived host bypasses in each address family.
pub const MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY: usize = 4_096;

const CAPTURE_PROGRAM_DIGEST_DOMAIN: &[u8] = b"Flux Capture Program\0canonical-schema-v1\0";

const MANDATORY_IPV4_PREFIX_SPECS: &[(u32, u8)] = &[
    (0x0000_0000, 8),
    (0x7f00_0000, 8),
    (0xa9fe_0000, 16),
    (0xe000_0000, 4),
    (0xf000_0000, 4),
    (0xffff_ffff, 32),
];

const MANDATORY_IPV6_PREFIX_SPECS: &[(u128, u8)] = &[
    (0, 128),
    (1, 128),
    (0x0000_0000_0000_0000_0000_ffff_0000_0000, 96),
    (0xfe80_0000_0000_0000_0000_0000_0000_0000, 10),
    (0xff00_0000_0000_0000_0000_0000_0000_0000, 8),
];

/// Linux UID accepted by the Capture Policy boundary.
///
/// `u32::MAX` is reserved as the kernel's invalid/no-identity sentinel.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CaptureUserId(u32);

impl CaptureUserId {
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value == u32::MAX {
            None
        } else {
            Some(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Linux GID accepted by the Capture Policy boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CaptureGroupId(u32);

impl CaptureGroupId {
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value == u32::MAX {
            None
        } else {
            Some(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Exact engine credentials used by the owner-match loop-prevention predicate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EngineCredentials {
    uid: CaptureUserId,
    gid: CaptureGroupId,
}

impl EngineCredentials {
    #[must_use]
    pub const fn new(uid: CaptureUserId, gid: CaptureGroupId) -> Self {
        Self { uid, gid }
    }

    #[must_use]
    pub const fn uid(self) -> CaptureUserId {
        self.uid
    }

    #[must_use]
    pub const fn gid(self) -> CaptureGroupId {
        self.gid
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaptureTrafficDomain {
    LocalOutput,
    ForwardedIngress,
}

/// Nonempty family/domain selection for Capture Program compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureTrafficScope {
    families: AddressHostFamilySelection,
    local_output: bool,
    forwarded_ingress: bool,
}

impl CaptureTrafficScope {
    pub const fn new(
        families: AddressHostFamilySelection,
        local_output: bool,
        forwarded_ingress: bool,
    ) -> Result<Self, CaptureTrafficScopeError> {
        if !local_output && !forwarded_ingress {
            return Err(CaptureTrafficScopeError::NoTrafficDomains);
        }
        Ok(Self {
            families,
            local_output,
            forwarded_ingress,
        })
    }

    #[must_use]
    pub const fn families(self) -> AddressHostFamilySelection {
        self.families
    }

    #[must_use]
    pub const fn includes_family(self, family: NetworkAddressFamily) -> bool {
        self.families.includes(family)
    }

    #[must_use]
    pub const fn includes_domain(self, domain: CaptureTrafficDomain) -> bool {
        match domain {
            CaptureTrafficDomain::LocalOutput => self.local_output,
            CaptureTrafficDomain::ForwardedIngress => self.forwarded_ingress,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureTrafficScopeError {
    NoTrafficDomains,
}

impl fmt::Display for CaptureTrafficScopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrafficDomains => {
                formatter.write_str("capture traffic scope enables no traffic domain")
            }
        }
    }
}

impl Error for CaptureTrafficScopeError {}

/// Family-preserving IP prefix used by packet-classification policy.
///
/// Unlike routing-address normalization, an IPv4-mapped IPv6 prefix remains IPv6 because the
/// Capture Program intentionally carries `::ffff:0:0/96`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CaptureIpPrefix {
    network: IpAddr,
    prefix_length: u8,
}

impl CaptureIpPrefix {
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, CaptureIpPrefixError> {
        let maximum = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_length > maximum {
            return Err(CaptureIpPrefixError {
                address,
                prefix_length,
            });
        }
        Ok(Self {
            network: canonical_network_address(address, prefix_length),
            prefix_length,
        })
    }

    #[must_use]
    pub const fn network(self) -> IpAddr {
        self.network
    }

    #[must_use]
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }

    #[must_use]
    pub const fn family(self) -> NetworkAddressFamily {
        address_family(self.network)
    }

    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        address_family(address) == self.family()
            && canonical_network_address(address, self.prefix_length) == self.network
    }

    #[must_use]
    pub fn covers(self, other: Self) -> bool {
        self.family() == other.family()
            && self.prefix_length <= other.prefix_length
            && self.contains(other.network)
    }

    const fn is_universal(self) -> bool {
        self.prefix_length == 0
    }
}

impl fmt::Display for CaptureIpPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_length)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureIpPrefixError {
    address: IpAddr,
    prefix_length: u8,
}

impl CaptureIpPrefixError {
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    #[must_use]
    pub const fn prefix_length(self) -> u8 {
        self.prefix_length
    }
}

impl fmt::Display for CaptureIpPrefixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "capture prefix {}/{} exceeds its address-family width",
            self.address, self.prefix_length
        )
    }
}

impl Error for CaptureIpPrefixError {}

/// Canonical configurable destination-bypass layer.
///
/// Mandatory invalid, loopback, link-local, multicast, and reserved exclusions are supplied by
/// the compiler and cannot be replaced by this input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureBypassPolicy {
    prefixes: Box<[CaptureIpPrefix]>,
}

impl CaptureBypassPolicy {
    pub fn new(
        prefixes: impl IntoIterator<Item = CaptureIpPrefix>,
    ) -> Result<Self, CaptureBypassPolicyError> {
        let mut unique = BTreeSet::new();
        for (raw_count, prefix) in prefixes.into_iter().enumerate() {
            if raw_count == MAX_CAPTURE_POLICY_PREFIX_INPUTS {
                return Err(CaptureBypassPolicyError::RawPrefixLimitExceeded {
                    maximum: MAX_CAPTURE_POLICY_PREFIX_INPUTS,
                    required_at_least: MAX_CAPTURE_POLICY_PREFIX_INPUTS + 1,
                });
            }
            unique.insert(prefix);
        }
        Ok(Self {
            prefixes: canonicalize_prefixes(unique.into_iter().collect()).into_boxed_slice(),
        })
    }

    #[must_use]
    pub fn prefixes(&self) -> &[CaptureIpPrefix] {
        &self.prefixes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureBypassPolicyError {
    RawPrefixLimitExceeded {
        maximum: usize,
        required_at_least: usize,
    },
}

impl fmt::Display for CaptureBypassPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawPrefixLimitExceeded {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "capture bypass policy supplies at least {required_at_least} raw prefixes but its absolute input limit is {maximum}"
            ),
        }
    }
}

impl Error for CaptureBypassPolicyError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaptureInterfaceSelectorKind {
    Exact,
    Prefix,
}

/// Backend-neutral exact or prefix interface match.
///
/// This type does not prove xtables renderability. In particular, a renderer must validate raw
/// bytes, trailing `+` ambiguity, and the extra wildcard byte for a 15-byte prefix before emitting
/// restore syntax.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CaptureInterfaceSelector {
    name: InterfaceName,
    kind: CaptureInterfaceSelectorKind,
}

impl CaptureInterfaceSelector {
    #[must_use]
    pub const fn exact(name: InterfaceName) -> Self {
        Self {
            name,
            kind: CaptureInterfaceSelectorKind::Exact,
        }
    }

    #[must_use]
    pub const fn prefix(name: InterfaceName) -> Self {
        Self {
            name,
            kind: CaptureInterfaceSelectorKind::Prefix,
        }
    }

    #[must_use]
    pub const fn name(self) -> InterfaceName {
        self.name
    }

    #[must_use]
    pub const fn kind(self) -> CaptureInterfaceSelectorKind {
        self.kind
    }

    #[must_use]
    pub fn matches(self, observed: InterfaceName) -> bool {
        match self.kind {
            CaptureInterfaceSelectorKind::Exact => self.name == observed,
            CaptureInterfaceSelectorKind::Prefix => {
                observed.as_bytes().starts_with(self.name.as_bytes())
            }
        }
    }
}

/// Canonical interface roles used by Capture Program policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureInterfacePolicy {
    excluded: Box<[CaptureInterfaceSelector]>,
    forwarded_proxy: Box<[CaptureInterfaceSelector]>,
    local_bypass: Box<[CaptureInterfaceSelector]>,
}

impl CaptureInterfacePolicy {
    pub fn new(
        excluded: impl IntoIterator<Item = CaptureInterfaceSelector>,
        forwarded_proxy: impl IntoIterator<Item = CaptureInterfaceSelector>,
        local_bypass: impl IntoIterator<Item = CaptureInterfaceSelector>,
    ) -> Result<Self, CaptureInterfacePolicyError> {
        let mut raw_count = 0;
        let excluded = collect_selectors(excluded, &mut raw_count)?;
        let mut forwarded_proxy = collect_selectors(forwarded_proxy, &mut raw_count)?;
        let mut local_bypass = collect_selectors(local_bypass, &mut raw_count)?;
        forwarded_proxy.retain(|candidate| {
            !excluded
                .iter()
                .copied()
                .any(|selector| selector_covers(selector, *candidate))
        });
        local_bypass.retain(|candidate| {
            !excluded
                .iter()
                .copied()
                .any(|selector| selector_covers(selector, *candidate))
        });
        Ok(Self {
            excluded: excluded.into_boxed_slice(),
            forwarded_proxy: forwarded_proxy.into_boxed_slice(),
            local_bypass: local_bypass.into_boxed_slice(),
        })
    }

    #[must_use]
    pub fn excluded(&self) -> &[CaptureInterfaceSelector] {
        &self.excluded
    }

    #[must_use]
    pub fn forwarded_proxy(&self) -> &[CaptureInterfaceSelector] {
        &self.forwarded_proxy
    }

    #[must_use]
    pub fn local_bypass(&self) -> &[CaptureInterfaceSelector] {
        &self.local_bypass
    }
}

fn collect_selectors(
    selectors: impl IntoIterator<Item = CaptureInterfaceSelector>,
    raw_count: &mut usize,
) -> Result<Vec<CaptureInterfaceSelector>, CaptureInterfacePolicyError> {
    let mut unique = BTreeSet::new();
    for selector in selectors {
        if *raw_count == MAX_CAPTURE_INTERFACE_SELECTORS {
            return Err(CaptureInterfacePolicyError::RawSelectorLimitExceeded {
                maximum: MAX_CAPTURE_INTERFACE_SELECTORS,
                required_at_least: MAX_CAPTURE_INTERFACE_SELECTORS + 1,
            });
        }
        *raw_count += 1;
        unique.insert(selector);
    }
    Ok(canonicalize_selectors(unique.into_iter().collect()))
}

fn canonicalize_selectors(
    mut selectors: Vec<CaptureInterfaceSelector>,
) -> Vec<CaptureInterfaceSelector> {
    selectors.sort_by_key(|selector| {
        (
            selector.name().as_bytes().len(),
            match selector.kind() {
                CaptureInterfaceSelectorKind::Prefix => 0,
                CaptureInterfaceSelectorKind::Exact => 1,
            },
            selector.name(),
        )
    });
    let mut canonical = Vec::new();
    for selector in selectors {
        if canonical
            .iter()
            .copied()
            .any(|retained| selector_covers(retained, selector))
        {
            continue;
        }
        canonical.push(selector);
    }
    canonical
}

fn selector_covers(
    retained: CaptureInterfaceSelector,
    candidate: CaptureInterfaceSelector,
) -> bool {
    match retained.kind() {
        CaptureInterfaceSelectorKind::Exact => {
            candidate.kind() == CaptureInterfaceSelectorKind::Exact
                && retained.name() == candidate.name()
        }
        CaptureInterfaceSelectorKind::Prefix => candidate
            .name()
            .as_bytes()
            .starts_with(retained.name().as_bytes()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureInterfacePolicyError {
    RawSelectorLimitExceeded {
        maximum: usize,
        required_at_least: usize,
    },
}

impl fmt::Display for CaptureInterfacePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RawSelectorLimitExceeded {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "capture interface policy supplies at least {required_at_least} raw selectors but its absolute input limit is {maximum}"
            ),
        }
    }
}

impl Error for CaptureInterfacePolicyError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaptureApplicationMode {
    All,
    Allowlist,
    Denylist,
}

/// Canonical resolved local-application policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureApplicationPolicy {
    mode: CaptureApplicationMode,
    uids: Box<[CaptureUserId]>,
}

impl CaptureApplicationPolicy {
    pub fn new(
        mode: CaptureApplicationMode,
        uids: impl IntoIterator<Item = CaptureUserId>,
    ) -> Result<Self, CaptureApplicationPolicyError> {
        let mut unique = BTreeSet::new();
        for (raw_count, uid) in uids.into_iter().enumerate() {
            if mode == CaptureApplicationMode::All {
                return Err(CaptureApplicationPolicyError::UnexpectedUidForAll);
            }
            if raw_count == MAX_CAPTURE_POLICY_UIDS {
                return Err(CaptureApplicationPolicyError::RawUidLimitExceeded {
                    maximum: MAX_CAPTURE_POLICY_UIDS,
                    required_at_least: MAX_CAPTURE_POLICY_UIDS + 1,
                });
            }
            unique.insert(uid);
        }
        Ok(Self {
            mode,
            uids: unique.into_iter().collect(),
        })
    }

    #[must_use]
    pub const fn mode(&self) -> CaptureApplicationMode {
        self.mode
    }

    #[must_use]
    pub fn uids(&self) -> &[CaptureUserId] {
        &self.uids
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureApplicationPolicyError {
    UnexpectedUidForAll,
    RawUidLimitExceeded {
        maximum: usize,
        required_at_least: usize,
    },
}

impl fmt::Display for CaptureApplicationPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedUidForAll => {
                formatter.write_str("capture application policy supplies UIDs for all-app mode")
            }
            Self::RawUidLimitExceeded {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "capture application policy supplies at least {required_at_least} raw UIDs but its absolute input limit is {maximum}"
            ),
        }
    }
}

impl Error for CaptureApplicationPolicyError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaptureTransportProtocol {
    Tcp,
    Udp,
    Other,
}

/// Nonempty set of transport protocols eligible for the final proxy action.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CaptureProtocolSet(u8);

impl CaptureProtocolSet {
    pub const TCP: Self = Self(1 << 0);
    pub const UDP: Self = Self(1 << 1);
    pub const TCP_AND_UDP: Self = Self(Self::TCP.0 | Self::UDP.0);

    pub const fn new(tcp: bool, udp: bool) -> Result<Self, CaptureProtocolSetError> {
        let bits = (tcp as u8) | ((udp as u8) << 1);
        if bits == 0 {
            Err(CaptureProtocolSetError::Empty)
        } else {
            Ok(Self(bits))
        }
    }

    #[must_use]
    pub const fn contains(self, protocol: CaptureTransportProtocol) -> bool {
        let bit = match protocol {
            CaptureTransportProtocol::Tcp => Self::TCP.0,
            CaptureTransportProtocol::Udp => Self::UDP.0,
            CaptureTransportProtocol::Other => 0,
        };
        self.0 & bit != 0
    }

    const fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureProtocolSetError {
    Empty,
}

impl fmt::Display for CaptureProtocolSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("capture proxy protocol set is empty"),
        }
    }
}

impl Error for CaptureProtocolSetError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaptureProgramResourceKind {
    ApplicationUids,
    ConfiguredInterfaceSelectors,
    DestinationHosts,
    DestinationPrefixes,
}

/// User-selected resource ceilings bounded by the compiled maxima.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureProgramBudget {
    prefixes_per_family: usize,
    application_uids: usize,
    interface_selectors: usize,
    hosts_per_family: usize,
}

impl CaptureProgramBudget {
    pub const fn new(
        prefixes_per_family: usize,
        application_uids: usize,
        interface_selectors: usize,
        hosts_per_family: usize,
    ) -> Result<Self, CaptureProgramBudgetError> {
        if prefixes_per_family > MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY {
            return Err(CaptureProgramBudgetError::ExceedsCompiledMaximum {
                resource: CaptureProgramResourceKind::DestinationPrefixes,
                requested: prefixes_per_family,
                maximum: MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY,
            });
        }
        if application_uids > MAX_CAPTURE_POLICY_UIDS {
            return Err(CaptureProgramBudgetError::ExceedsCompiledMaximum {
                resource: CaptureProgramResourceKind::ApplicationUids,
                requested: application_uids,
                maximum: MAX_CAPTURE_POLICY_UIDS,
            });
        }
        if interface_selectors > MAX_CAPTURE_INTERFACE_SELECTORS {
            return Err(CaptureProgramBudgetError::ExceedsCompiledMaximum {
                resource: CaptureProgramResourceKind::ConfiguredInterfaceSelectors,
                requested: interface_selectors,
                maximum: MAX_CAPTURE_INTERFACE_SELECTORS,
            });
        }
        if hosts_per_family > MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY {
            return Err(CaptureProgramBudgetError::ExceedsCompiledMaximum {
                resource: CaptureProgramResourceKind::DestinationHosts,
                requested: hosts_per_family,
                maximum: MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY,
            });
        }
        Ok(Self {
            prefixes_per_family,
            application_uids,
            interface_selectors,
            hosts_per_family,
        })
    }

    #[must_use]
    pub const fn prefixes_per_family(self) -> usize {
        self.prefixes_per_family
    }

    #[must_use]
    pub const fn application_uids(self) -> usize {
        self.application_uids
    }

    #[must_use]
    pub const fn interface_selectors(self) -> usize {
        self.interface_selectors
    }

    #[must_use]
    pub const fn hosts_per_family(self) -> usize {
        self.hosts_per_family
    }
}

impl Default for CaptureProgramBudget {
    fn default() -> Self {
        Self {
            prefixes_per_family: MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY,
            application_uids: MAX_CAPTURE_POLICY_UIDS,
            interface_selectors: MAX_CAPTURE_INTERFACE_SELECTORS,
            hosts_per_family: MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureProgramBudgetError {
    ExceedsCompiledMaximum {
        resource: CaptureProgramResourceKind,
        requested: usize,
        maximum: usize,
    },
}

impl fmt::Display for CaptureProgramBudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceedsCompiledMaximum {
                resource,
                requested,
                maximum,
            } => write!(
                formatter,
                "capture budget requests {requested} {resource:?} but the compiled maximum is {maximum}"
            ),
        }
    }
}

impl Error for CaptureProgramBudgetError {}

/// Pure inputs to Capture Program compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureProgramRequest {
    scope: CaptureTrafficScope,
    engine_credentials: EngineCredentials,
    configured_bypass: CaptureBypassPolicy,
    host_bypass: Option<AddressHostSetPlan>,
    interfaces: CaptureInterfacePolicy,
    applications: CaptureApplicationPolicy,
    proxy_protocols: CaptureProtocolSet,
    budget: CaptureProgramBudget,
}

impl CaptureProgramRequest {
    #[must_use]
    pub const fn new(
        scope: CaptureTrafficScope,
        engine_credentials: EngineCredentials,
        configured_bypass: CaptureBypassPolicy,
        host_bypass: Option<AddressHostSetPlan>,
        interfaces: CaptureInterfacePolicy,
        applications: CaptureApplicationPolicy,
        proxy_protocols: CaptureProtocolSet,
    ) -> Self {
        Self {
            scope,
            engine_credentials,
            configured_bypass,
            host_bypass,
            interfaces,
            applications,
            proxy_protocols,
            budget: CaptureProgramBudget {
                prefixes_per_family: MAX_CAPTURE_POLICY_PREFIXES_PER_FAMILY,
                application_uids: MAX_CAPTURE_POLICY_UIDS,
                interface_selectors: MAX_CAPTURE_INTERFACE_SELECTORS,
                hosts_per_family: MAX_CAPTURE_HOST_ADDRESSES_PER_FAMILY,
            },
        }
    }

    #[must_use]
    pub const fn with_budget(mut self, budget: CaptureProgramBudget) -> Self {
        self.budget = budget;
        self
    }
}

/// Fixed target-policy stage numbers from technical specification section 8.1.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CaptureDecisionStage {
    TrafficScope = 1,
    LoopPrevention = 2,
    MandatorySafety = 3,
    ConfigurableBypass = 4,
    EstablishedFlowCache = 5,
    InterfaceRole = 6,
    ApplicationPolicy = 7,
    ProtocolSafety = 8,
    ProxyAction = 9,
    DirectDefault = 10,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaptureInterfaceDirection {
    Input,
    Output,
}

/// Predicate in one ordered, terminal Capture Program clause.
///
/// Every list is one OR-membership set. `LocalUidNotIn` and `InterfaceDoesNotMatch` negate the
/// complete set, not each member independently; backend expansion must preserve that meaning and
/// re-check its own rule budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapturePredicate {
    Any,
    EngineCredentials(EngineCredentials),
    DestinationPrefixes(Box<[CaptureIpPrefix]>),
    DestinationHosts(Box<[IpAddr]>),
    InterfaceMatches {
        direction: CaptureInterfaceDirection,
        selectors: Box<[CaptureInterfaceSelector]>,
    },
    InterfaceDoesNotMatch {
        direction: CaptureInterfaceDirection,
        selectors: Box<[CaptureInterfaceSelector]>,
    },
    LocalUidIn(Box<[CaptureUserId]>),
    LocalUidNotIn(Box<[CaptureUserId]>),
    ProtocolNotIn(CaptureProtocolSet),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CaptureClauseDecision {
    Direct,
    Proxy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureClause {
    stage: CaptureDecisionStage,
    predicate: CapturePredicate,
    decision: CaptureClauseDecision,
}

impl CaptureClause {
    const fn new(
        stage: CaptureDecisionStage,
        predicate: CapturePredicate,
        decision: CaptureClauseDecision,
    ) -> Self {
        Self {
            stage,
            predicate,
            decision,
        }
    }

    #[must_use]
    pub const fn stage(&self) -> CaptureDecisionStage {
        self.stage
    }

    #[must_use]
    pub const fn predicate(&self) -> &CapturePredicate {
        &self.predicate
    }

    #[must_use]
    pub const fn decision(&self) -> CaptureClauseDecision {
        self.decision
    }
}

/// One family/domain program. Local and forwarded programs never share UID predicates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureDomainProgram {
    family: NetworkAddressFamily,
    domain: CaptureTrafficDomain,
    clauses: Box<[CaptureClause]>,
}

impl CaptureDomainProgram {
    #[must_use]
    pub const fn family(&self) -> NetworkAddressFamily {
        self.family
    }

    #[must_use]
    pub const fn domain(&self) -> CaptureTrafficDomain {
        self.domain
    }

    #[must_use]
    pub fn clauses(&self) -> &[CaptureClause] {
        &self.clauses
    }
}

/// Domain-separated SHA-256 of canonical semantic programs only.
///
/// Generation identity, timestamps, source snapshot/epoch, resource limit knobs, writer state,
/// and activation evidence are deliberately excluded.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CaptureProgramDigest([u8; 32]);

impl CaptureProgramDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureProgramResourceUsage {
    ipv4_prefixes: usize,
    ipv6_prefixes: usize,
    ipv4_hosts: usize,
    ipv6_hosts: usize,
    application_uids: usize,
    interface_selectors: usize,
    domain_programs: usize,
    clauses: usize,
}

impl CaptureProgramResourceUsage {
    #[must_use]
    pub const fn prefixes(self, family: NetworkAddressFamily) -> usize {
        match family {
            NetworkAddressFamily::Ipv4 => self.ipv4_prefixes,
            NetworkAddressFamily::Ipv6 => self.ipv6_prefixes,
        }
    }

    #[must_use]
    pub const fn hosts(self, family: NetworkAddressFamily) -> usize {
        match family {
            NetworkAddressFamily::Ipv4 => self.ipv4_hosts,
            NetworkAddressFamily::Ipv6 => self.ipv6_hosts,
        }
    }

    #[must_use]
    pub const fn application_uids(self) -> usize {
        self.application_uids
    }

    #[must_use]
    pub const fn interface_selectors(self) -> usize {
        self.interface_selectors
    }

    #[must_use]
    pub const fn domain_programs(self) -> usize {
        self.domain_programs
    }

    #[must_use]
    pub const fn clauses(self) -> usize {
        self.clauses
    }
}

/// Backend-neutral policy compiled for one Desired State.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureProgram {
    schema_version: u16,
    programs: Box<[CaptureDomainProgram]>,
    digest: CaptureProgramDigest,
    usage: CaptureProgramResourceUsage,
}

impl CaptureProgram {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub fn programs(&self) -> &[CaptureDomainProgram] {
        &self.programs
    }

    #[must_use]
    pub const fn digest(&self) -> CaptureProgramDigest {
        self.digest
    }

    #[must_use]
    pub const fn usage(&self) -> CaptureProgramResourceUsage {
        self.usage
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressHostSetProvenance {
    snapshot_id: NetworkInventorySnapshotId,
    epoch: NetworkEpoch,
    families: AddressHostFamilySelection,
}

impl AddressHostSetProvenance {
    #[must_use]
    pub const fn snapshot_id(self) -> NetworkInventorySnapshotId {
        self.snapshot_id
    }

    #[must_use]
    pub const fn epoch(self) -> NetworkEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn families(self) -> AddressHostFamilySelection {
        self.families
    }
}

/// Compiled policy plus the inventory provenance excluded from its semantic digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureProgramCompilation {
    program: CaptureProgram,
    address_host_set_provenance: Option<AddressHostSetProvenance>,
}

impl CaptureProgramCompilation {
    #[must_use]
    pub const fn program(&self) -> &CaptureProgram {
        &self.program
    }

    #[must_use]
    pub const fn address_host_set_provenance(&self) -> Option<AddressHostSetProvenance> {
        self.address_host_set_provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureProgramCompileError {
    ResourceBudgetExceeded {
        resource: CaptureProgramResourceKind,
        family: Option<NetworkAddressFamily>,
        maximum: usize,
        required_at_least: usize,
    },
}

impl fmt::Display for CaptureProgramCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceBudgetExceeded {
                resource,
                family,
                maximum,
                required_at_least,
            } => {
                if let Some(family) = family {
                    write!(
                        formatter,
                        "Capture Program requires {required_at_least} {resource:?} for {family:?} but its budget is {maximum}"
                    )
                } else {
                    write!(
                        formatter,
                        "Capture Program requires {required_at_least} {resource:?} but its budget is {maximum}"
                    )
                }
            }
        }
    }
}

impl Error for CaptureProgramCompileError {}

/// Compile deterministic, ordered, non-authorizing target policy without performing I/O.
pub fn compile_capture_program(
    request: CaptureProgramRequest,
) -> Result<CaptureProgramCompilation, CaptureProgramCompileError> {
    let CaptureProgramRequest {
        scope,
        engine_credentials,
        configured_bypass,
        host_bypass,
        interfaces,
        applications,
        proxy_protocols,
        budget,
    } = request;

    let mandatory = mandatory_safety_prefixes();
    let mut family_inputs = Vec::new();
    for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
        if !scope.includes_family(family) {
            continue;
        }

        let mandatory = prefixes_for_family(&mandatory, family);
        let configured = configured_bypass
            .prefixes()
            .iter()
            .copied()
            .filter(|prefix| prefix.family() == family)
            .filter(|prefix| {
                !mandatory
                    .iter()
                    .copied()
                    .any(|mandatory| mandatory.covers(*prefix))
            })
            .collect::<Vec<_>>();
        let hosts = canonical_hosts(host_bypass.as_ref(), family, mandatory.iter().copied());

        ensure_family_budget(
            CaptureProgramResourceKind::DestinationPrefixes,
            family,
            budget.prefixes_per_family(),
            mandatory.len() + configured.len(),
        )?;
        ensure_family_budget(
            CaptureProgramResourceKind::DestinationHosts,
            family,
            budget.hosts_per_family(),
            hosts.len(),
        )?;

        family_inputs.push(FamilyProgramInput {
            family,
            mandatory,
            configured,
            hosts,
        });
    }

    let mut programs = Vec::new();
    for input in &family_inputs {
        if scope.includes_domain(CaptureTrafficDomain::LocalOutput) {
            programs.push(build_local_program(
                input,
                engine_credentials,
                &interfaces,
                &applications,
                proxy_protocols,
            ));
        }
        if scope.includes_domain(CaptureTrafficDomain::ForwardedIngress) {
            programs.push(build_forwarded_program(input, &interfaces, proxy_protocols));
        }
    }

    let application_uids = emitted_application_uids(&programs);
    ensure_budget(
        CaptureProgramResourceKind::ApplicationUids,
        budget.application_uids(),
        application_uids,
    )?;

    let interface_selectors = emitted_interface_selectors(&programs);
    ensure_budget(
        CaptureProgramResourceKind::ConfiguredInterfaceSelectors,
        budget.interface_selectors(),
        interface_selectors,
    )?;

    let usage = CaptureProgramResourceUsage {
        ipv4_prefixes: family_inputs
            .iter()
            .find(|input| input.family == NetworkAddressFamily::Ipv4)
            .map_or(0, FamilyProgramInput::prefix_count),
        ipv6_prefixes: family_inputs
            .iter()
            .find(|input| input.family == NetworkAddressFamily::Ipv6)
            .map_or(0, FamilyProgramInput::prefix_count),
        ipv4_hosts: family_inputs
            .iter()
            .find(|input| input.family == NetworkAddressFamily::Ipv4)
            .map_or(0, |input| input.hosts.len()),
        ipv6_hosts: family_inputs
            .iter()
            .find(|input| input.family == NetworkAddressFamily::Ipv6)
            .map_or(0, |input| input.hosts.len()),
        application_uids,
        interface_selectors,
        domain_programs: programs.len(),
        clauses: programs.iter().map(|program| program.clauses.len()).sum(),
    };

    let digest = digest_programs(&programs);
    let address_host_set_provenance = host_bypass.as_ref().map(|plan| AddressHostSetProvenance {
        snapshot_id: plan.snapshot_id(),
        epoch: plan.epoch(),
        families: plan.families(),
    });

    Ok(CaptureProgramCompilation {
        program: CaptureProgram {
            schema_version: CAPTURE_PROGRAM_SCHEMA_VERSION,
            programs: programs.into_boxed_slice(),
            digest,
            usage,
        },
        address_host_set_provenance,
    })
}

struct FamilyProgramInput {
    family: NetworkAddressFamily,
    mandatory: Vec<CaptureIpPrefix>,
    configured: Vec<CaptureIpPrefix>,
    hosts: Vec<IpAddr>,
}

impl FamilyProgramInput {
    fn prefix_count(&self) -> usize {
        self.mandatory.len() + self.configured.len()
    }

    fn configured_bypasses_everything(&self) -> bool {
        self.configured
            .iter()
            .copied()
            .any(CaptureIpPrefix::is_universal)
    }
}

fn build_local_program(
    input: &FamilyProgramInput,
    engine_credentials: EngineCredentials,
    interfaces: &CaptureInterfacePolicy,
    applications: &CaptureApplicationPolicy,
    proxy_protocols: CaptureProtocolSet,
) -> CaptureDomainProgram {
    let mut clauses = vec![CaptureClause::new(
        CaptureDecisionStage::LoopPrevention,
        CapturePredicate::EngineCredentials(engine_credentials),
        CaptureClauseDecision::Direct,
    )];
    push_destination_clauses(&mut clauses, input);
    if input.configured_bypasses_everything() {
        return domain_program(input.family, CaptureTrafficDomain::LocalOutput, clauses);
    }

    push_interface_match_clause(
        &mut clauses,
        CaptureDecisionStage::InterfaceRole,
        CaptureInterfaceDirection::Output,
        interfaces.excluded(),
    );
    push_interface_match_clause(
        &mut clauses,
        CaptureDecisionStage::InterfaceRole,
        CaptureInterfaceDirection::Output,
        interfaces.local_bypass(),
    );

    match applications.mode() {
        CaptureApplicationMode::All => {}
        CaptureApplicationMode::Allowlist if applications.uids().is_empty() => {
            clauses.push(CaptureClause::new(
                CaptureDecisionStage::ApplicationPolicy,
                CapturePredicate::Any,
                CaptureClauseDecision::Direct,
            ));
            return domain_program(input.family, CaptureTrafficDomain::LocalOutput, clauses);
        }
        CaptureApplicationMode::Allowlist => clauses.push(CaptureClause::new(
            CaptureDecisionStage::ApplicationPolicy,
            CapturePredicate::LocalUidNotIn(applications.uids().to_vec().into_boxed_slice()),
            CaptureClauseDecision::Direct,
        )),
        CaptureApplicationMode::Denylist if applications.uids().is_empty() => {}
        CaptureApplicationMode::Denylist => clauses.push(CaptureClause::new(
            CaptureDecisionStage::ApplicationPolicy,
            CapturePredicate::LocalUidIn(applications.uids().to_vec().into_boxed_slice()),
            CaptureClauseDecision::Direct,
        )),
    }

    push_proxy_tail(&mut clauses, proxy_protocols);
    domain_program(input.family, CaptureTrafficDomain::LocalOutput, clauses)
}

fn build_forwarded_program(
    input: &FamilyProgramInput,
    interfaces: &CaptureInterfacePolicy,
    proxy_protocols: CaptureProtocolSet,
) -> CaptureDomainProgram {
    let loopback = [CaptureInterfaceSelector::exact(
        InterfaceName::new(b"lo").expect("the Linux loopback interface name is valid"),
    )];
    let mut clauses = Vec::new();
    push_prefix_clause(
        &mut clauses,
        CaptureDecisionStage::MandatorySafety,
        &input.mandatory,
    );
    push_host_clause(&mut clauses, &input.hosts);
    push_interface_match_clause(
        &mut clauses,
        CaptureDecisionStage::MandatorySafety,
        CaptureInterfaceDirection::Input,
        &loopback,
    );
    push_prefix_clause(
        &mut clauses,
        CaptureDecisionStage::ConfigurableBypass,
        &input.configured,
    );
    if input.configured_bypasses_everything() {
        return domain_program(
            input.family,
            CaptureTrafficDomain::ForwardedIngress,
            clauses,
        );
    }

    push_interface_match_clause(
        &mut clauses,
        CaptureDecisionStage::InterfaceRole,
        CaptureInterfaceDirection::Input,
        interfaces.excluded(),
    );
    if interfaces.forwarded_proxy().is_empty() {
        clauses.push(CaptureClause::new(
            CaptureDecisionStage::InterfaceRole,
            CapturePredicate::Any,
            CaptureClauseDecision::Direct,
        ));
        return domain_program(
            input.family,
            CaptureTrafficDomain::ForwardedIngress,
            clauses,
        );
    }
    clauses.push(CaptureClause::new(
        CaptureDecisionStage::InterfaceRole,
        CapturePredicate::InterfaceDoesNotMatch {
            direction: CaptureInterfaceDirection::Input,
            selectors: interfaces.forwarded_proxy().to_vec().into_boxed_slice(),
        },
        CaptureClauseDecision::Direct,
    ));

    push_proxy_tail(&mut clauses, proxy_protocols);
    domain_program(
        input.family,
        CaptureTrafficDomain::ForwardedIngress,
        clauses,
    )
}

fn push_destination_clauses(clauses: &mut Vec<CaptureClause>, input: &FamilyProgramInput) {
    push_prefix_clause(
        clauses,
        CaptureDecisionStage::MandatorySafety,
        &input.mandatory,
    );
    push_host_clause(clauses, &input.hosts);
    push_prefix_clause(
        clauses,
        CaptureDecisionStage::ConfigurableBypass,
        &input.configured,
    );
}

fn push_prefix_clause(
    clauses: &mut Vec<CaptureClause>,
    stage: CaptureDecisionStage,
    prefixes: &[CaptureIpPrefix],
) {
    if !prefixes.is_empty() {
        clauses.push(CaptureClause::new(
            stage,
            CapturePredicate::DestinationPrefixes(prefixes.to_vec().into_boxed_slice()),
            CaptureClauseDecision::Direct,
        ));
    }
}

fn push_host_clause(clauses: &mut Vec<CaptureClause>, hosts: &[IpAddr]) {
    if !hosts.is_empty() {
        clauses.push(CaptureClause::new(
            CaptureDecisionStage::MandatorySafety,
            CapturePredicate::DestinationHosts(hosts.to_vec().into_boxed_slice()),
            CaptureClauseDecision::Direct,
        ));
    }
}

fn push_interface_match_clause(
    clauses: &mut Vec<CaptureClause>,
    stage: CaptureDecisionStage,
    direction: CaptureInterfaceDirection,
    selectors: &[CaptureInterfaceSelector],
) {
    if !selectors.is_empty() {
        clauses.push(CaptureClause::new(
            stage,
            CapturePredicate::InterfaceMatches {
                direction,
                selectors: selectors.to_vec().into_boxed_slice(),
            },
            CaptureClauseDecision::Direct,
        ));
    }
}

fn push_proxy_tail(clauses: &mut Vec<CaptureClause>, protocols: CaptureProtocolSet) {
    clauses.push(CaptureClause::new(
        CaptureDecisionStage::ProtocolSafety,
        CapturePredicate::ProtocolNotIn(protocols),
        CaptureClauseDecision::Direct,
    ));
    clauses.push(CaptureClause::new(
        CaptureDecisionStage::ProxyAction,
        CapturePredicate::Any,
        CaptureClauseDecision::Proxy,
    ));
}

fn domain_program(
    family: NetworkAddressFamily,
    domain: CaptureTrafficDomain,
    clauses: Vec<CaptureClause>,
) -> CaptureDomainProgram {
    debug_assert!(
        clauses
            .windows(2)
            .all(|pair| pair[0].stage <= pair[1].stage)
    );
    CaptureDomainProgram {
        family,
        domain,
        clauses: clauses.into_boxed_slice(),
    }
}

fn emitted_application_uids(programs: &[CaptureDomainProgram]) -> usize {
    programs
        .iter()
        .flat_map(|program| program.clauses.iter())
        .filter(|clause| clause.stage == CaptureDecisionStage::ApplicationPolicy)
        .flat_map(|clause| match &clause.predicate {
            CapturePredicate::LocalUidIn(uids) | CapturePredicate::LocalUidNotIn(uids) => {
                uids.iter().copied()
            }
            _ => [].iter().copied(),
        })
        .collect::<BTreeSet<_>>()
        .len()
}

fn emitted_interface_selectors(programs: &[CaptureDomainProgram]) -> usize {
    programs
        .iter()
        .flat_map(|program| program.clauses.iter())
        .filter(|clause| clause.stage == CaptureDecisionStage::InterfaceRole)
        .flat_map(|clause| match &clause.predicate {
            CapturePredicate::InterfaceMatches { selectors, .. }
            | CapturePredicate::InterfaceDoesNotMatch { selectors, .. } => {
                selectors.iter().copied()
            }
            _ => [].iter().copied(),
        })
        .collect::<BTreeSet<_>>()
        .len()
}

fn ensure_family_budget(
    resource: CaptureProgramResourceKind,
    family: NetworkAddressFamily,
    maximum: usize,
    required: usize,
) -> Result<(), CaptureProgramCompileError> {
    if required > maximum {
        Err(CaptureProgramCompileError::ResourceBudgetExceeded {
            resource,
            family: Some(family),
            maximum,
            required_at_least: required,
        })
    } else {
        Ok(())
    }
}

fn ensure_budget(
    resource: CaptureProgramResourceKind,
    maximum: usize,
    required: usize,
) -> Result<(), CaptureProgramCompileError> {
    if required > maximum {
        Err(CaptureProgramCompileError::ResourceBudgetExceeded {
            resource,
            family: None,
            maximum,
            required_at_least: required,
        })
    } else {
        Ok(())
    }
}

fn mandatory_safety_prefixes() -> Vec<CaptureIpPrefix> {
    let prefixes = MANDATORY_IPV4_PREFIX_SPECS
        .iter()
        .map(|(network, prefix_length)| {
            CaptureIpPrefix::new(IpAddr::V4(Ipv4Addr::from(*network)), *prefix_length)
                .expect("the built-in IPv4 mandatory safety prefix is valid")
        })
        .chain(
            MANDATORY_IPV6_PREFIX_SPECS
                .iter()
                .map(|(network, prefix_length)| {
                    CaptureIpPrefix::new(IpAddr::V6(Ipv6Addr::from(*network)), *prefix_length)
                        .expect("the built-in IPv6 mandatory safety prefix is valid")
                }),
        )
        .collect();
    canonicalize_prefixes(prefixes)
}

fn prefixes_for_family(
    prefixes: &[CaptureIpPrefix],
    family: NetworkAddressFamily,
) -> Vec<CaptureIpPrefix> {
    prefixes
        .iter()
        .copied()
        .filter(|prefix| prefix.family() == family)
        .collect()
}

fn canonicalize_prefixes(mut prefixes: Vec<CaptureIpPrefix>) -> Vec<CaptureIpPrefix> {
    prefixes.sort_by_key(|prefix| {
        (
            family_tag(prefix.family()),
            prefix_interval(*prefix).0,
            prefix.prefix_length(),
        )
    });
    let mut canonical = Vec::new();
    let mut covered_family = None;
    let mut covered_until = 0;
    for prefix in prefixes {
        let family = prefix.family();
        let (start, end) = prefix_interval(prefix);
        if covered_family == Some(family) && start <= covered_until {
            continue;
        }
        canonical.push(prefix);
        covered_family = Some(family);
        covered_until = end;
    }
    canonical
}

fn canonical_hosts(
    plan: Option<&AddressHostSetPlan>,
    family: NetworkAddressFamily,
    bypasses: impl IntoIterator<Item = CaptureIpPrefix>,
) -> Vec<IpAddr> {
    let bypasses = bypasses.into_iter().collect::<Vec<_>>();
    plan.into_iter()
        .flat_map(AddressHostSetPlan::hosts)
        .copied()
        .filter(|address| address_family(*address) == family)
        .filter(|address| {
            !bypasses
                .iter()
                .copied()
                .any(|prefix| prefix.contains(*address))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn digest_programs(programs: &[CaptureDomainProgram]) -> CaptureProgramDigest {
    let mut digest = Sha256::new();
    digest.update(CAPTURE_PROGRAM_DIGEST_DOMAIN);
    digest.update(CAPTURE_PROGRAM_SCHEMA_VERSION.to_be_bytes());
    digest.update(length_bytes(programs.len()));
    for program in programs {
        digest.update([family_tag(program.family)]);
        digest.update([domain_tag(program.domain)]);
        digest.update(length_bytes(program.clauses.len()));
        for clause in &program.clauses {
            digest.update([clause.stage as u8]);
            digest.update([decision_tag(clause.decision)]);
            digest_predicate(&mut digest, &clause.predicate);
        }
    }
    CaptureProgramDigest(digest.finalize().into())
}

fn digest_predicate(digest: &mut Sha256, predicate: &CapturePredicate) {
    match predicate {
        CapturePredicate::Any => digest.update([0]),
        CapturePredicate::EngineCredentials(credentials) => {
            digest.update([1]);
            digest.update(credentials.uid().get().to_be_bytes());
            digest.update(credentials.gid().get().to_be_bytes());
        }
        CapturePredicate::DestinationPrefixes(prefixes) => {
            digest.update([2]);
            digest.update(length_bytes(prefixes.len()));
            for prefix in prefixes {
                digest_ip(digest, prefix.network());
                digest.update([prefix.prefix_length()]);
            }
        }
        CapturePredicate::DestinationHosts(hosts) => {
            digest.update([3]);
            digest.update(length_bytes(hosts.len()));
            for host in hosts {
                digest_ip(digest, *host);
            }
        }
        CapturePredicate::InterfaceMatches {
            direction,
            selectors,
        } => {
            digest.update([4, interface_direction_tag(*direction)]);
            digest_selectors(digest, selectors);
        }
        CapturePredicate::InterfaceDoesNotMatch {
            direction,
            selectors,
        } => {
            digest.update([5, interface_direction_tag(*direction)]);
            digest_selectors(digest, selectors);
        }
        CapturePredicate::LocalUidIn(uids) => {
            digest.update([6]);
            digest_uids(digest, uids);
        }
        CapturePredicate::LocalUidNotIn(uids) => {
            digest.update([7]);
            digest_uids(digest, uids);
        }
        CapturePredicate::ProtocolNotIn(protocols) => {
            digest.update([8, protocols.bits()]);
        }
    }
}

fn digest_selectors(digest: &mut Sha256, selectors: &[CaptureInterfaceSelector]) {
    digest.update(length_bytes(selectors.len()));
    for selector in selectors {
        digest.update([match selector.kind() {
            CaptureInterfaceSelectorKind::Exact => 0,
            CaptureInterfaceSelectorKind::Prefix => 1,
        }]);
        let name = selector.name();
        let bytes = name.as_bytes();
        digest.update([u8::try_from(bytes.len()).expect("Linux interface-name length fits u8")]);
        digest.update(bytes);
    }
}

fn digest_uids(digest: &mut Sha256, uids: &[CaptureUserId]) {
    digest.update(length_bytes(uids.len()));
    for uid in uids {
        digest.update(uid.get().to_be_bytes());
    }
}

fn digest_ip(digest: &mut Sha256, address: IpAddr) {
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

fn length_bytes(length: usize) -> [u8; 4] {
    u32::try_from(length)
        .expect("Capture Program compiled bounds fit u32")
        .to_be_bytes()
}

const fn family_tag(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 4,
        NetworkAddressFamily::Ipv6 => 6,
    }
}

const fn domain_tag(domain: CaptureTrafficDomain) -> u8 {
    match domain {
        CaptureTrafficDomain::LocalOutput => 0,
        CaptureTrafficDomain::ForwardedIngress => 1,
    }
}

const fn decision_tag(decision: CaptureClauseDecision) -> u8 {
    match decision {
        CaptureClauseDecision::Direct => 0,
        CaptureClauseDecision::Proxy => 1,
    }
}

const fn interface_direction_tag(direction: CaptureInterfaceDirection) -> u8 {
    match direction {
        CaptureInterfaceDirection::Input => 0,
        CaptureInterfaceDirection::Output => 1,
    }
}

const fn address_family(address: IpAddr) -> NetworkAddressFamily {
    match address {
        IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
        IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
    }
}

fn prefix_interval(prefix: CaptureIpPrefix) -> (u128, u128) {
    let (start, width) = match prefix.network() {
        IpAddr::V4(address) => (u128::from(u32::from(address)), 32),
        IpAddr::V6(address) => (u128::from_be_bytes(address.octets()), 128),
    };
    let host_bits = width - u32::from(prefix.prefix_length());
    let host_mask = match host_bits {
        0 => 0,
        128 => u128::MAX,
        bits => (1_u128 << bits) - 1,
    };
    (start, start | host_mask)
}

fn canonical_network_address(address: IpAddr, prefix_length: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            let network = if prefix_length == 0 {
                0
            } else {
                value & (u32::MAX << (32 - prefix_length))
            };
            IpAddr::V4(Ipv4Addr::from(network))
        }
        IpAddr::V6(address) => {
            let value = u128::from_be_bytes(address.octets());
            let network = if prefix_length == 0 {
                0
            } else {
                value & (u128::MAX << (128 - prefix_length))
            };
            IpAddr::V6(Ipv6Addr::from(network.to_be_bytes()))
        }
    }
}
