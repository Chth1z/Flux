use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};

use crate::{
    AndroidNetdSourceProfile, InterfaceName, ReviewedPolicyCatalogEntryId, RouteTableId,
    RulePriority, Sha256Digest,
};

pub const MAX_REVIEWED_CANARY_FACILITY_ADDRESS_CANDIDATES: usize = 8;
pub const MAX_REVIEWED_CANARY_FACILITY_PORT_CANDIDATES: usize = 8;
pub const MAX_REVIEWED_CANARY_EARLY_UID_LOOKUP_PRIORITIES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReviewedCanaryRoleCredentials {
    probe_uid: NonZeroU32,
    probe_gid: NonZeroU32,
    engine_uid: NonZeroU32,
    engine_gid: NonZeroU32,
}

impl ReviewedCanaryRoleCredentials {
    fn new(
        probe_uid: u32,
        probe_gid: u32,
        engine_uid: u32,
        engine_gid: u32,
    ) -> Result<Self, ReviewedCanaryFacilityPolicyError> {
        let probe_uid = NonZeroU32::new(probe_uid)
            .filter(|value| value.get() != u32::MAX)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidRoleCredentials)?;
        let probe_gid = NonZeroU32::new(probe_gid)
            .filter(|value| value.get() != u32::MAX)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidRoleCredentials)?;
        let engine_uid = NonZeroU32::new(engine_uid)
            .filter(|value| value.get() != u32::MAX)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidRoleCredentials)?;
        let engine_gid = NonZeroU32::new(engine_gid)
            .filter(|value| value.get() != u32::MAX)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidRoleCredentials)?;
        if probe_uid == engine_uid || probe_gid == engine_gid {
            return Err(ReviewedCanaryFacilityPolicyError::InvalidRoleCredentials);
        }
        Ok(Self {
            probe_uid,
            probe_gid,
            engine_uid,
            engine_gid,
        })
    }

    #[must_use]
    pub const fn probe_uid(self) -> NonZeroU32 {
        self.probe_uid
    }

    #[must_use]
    pub const fn probe_gid(self) -> NonZeroU32 {
        self.probe_gid
    }

    #[must_use]
    pub const fn engine_uid(self) -> NonZeroU32 {
        self.engine_uid
    }

    #[must_use]
    pub const fn engine_gid(self) -> NonZeroU32 {
        self.engine_gid
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReviewedCanaryFacilityAddressCandidate {
    daemon_ipv4: Ipv4Addr,
    peer_ipv4: Ipv4Addr,
    daemon_ipv6: Option<Ipv6Addr>,
    peer_ipv6: Option<Ipv6Addr>,
}

impl ReviewedCanaryFacilityAddressCandidate {
    fn new(
        daemon_ipv4: Ipv4Addr,
        peer_ipv4: Ipv4Addr,
        daemon_ipv6: Option<Ipv6Addr>,
        peer_ipv6: Option<Ipv6Addr>,
    ) -> Result<Self, ReviewedCanaryFacilityPolicyError> {
        if daemon_ipv4 == peer_ipv4
            || ipv4_forbidden(daemon_ipv4)
            || ipv4_forbidden(peer_ipv4)
            || daemon_ipv6.is_some() != peer_ipv6.is_some()
            || daemon_ipv6
                .is_some_and(|address| Some(address) == peer_ipv6 || ipv6_forbidden(address))
            || peer_ipv6.is_some_and(ipv6_forbidden)
        {
            return Err(ReviewedCanaryFacilityPolicyError::InvalidAddressCandidate);
        }
        Ok(Self {
            daemon_ipv4,
            peer_ipv4,
            daemon_ipv6,
            peer_ipv6,
        })
    }

    #[must_use]
    pub const fn daemon_ipv4(self) -> Ipv4Addr {
        self.daemon_ipv4
    }

    #[must_use]
    pub const fn peer_ipv4(self) -> Ipv4Addr {
        self.peer_ipv4
    }

    #[must_use]
    pub const fn daemon_ipv6(self) -> Option<Ipv6Addr> {
        self.daemon_ipv6
    }

    #[must_use]
    pub const fn peer_ipv6(self) -> Option<Ipv6Addr> {
        self.peer_ipv6
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReviewedCanaryResponderPortCandidate {
    tcp_echo: NonZeroU16,
    udp_echo: NonZeroU16,
    dns: NonZeroU16,
}

impl ReviewedCanaryResponderPortCandidate {
    fn new(
        tcp_echo: u16,
        udp_echo: u16,
        dns: u16,
    ) -> Result<Self, ReviewedCanaryFacilityPolicyError> {
        let tcp_echo = NonZeroU16::new(tcp_echo)
            .filter(|value| value.get() != u16::MAX)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidPortCandidate)?;
        let udp_echo = NonZeroU16::new(udp_echo)
            .filter(|value| value.get() != u16::MAX)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidPortCandidate)?;
        let dns = NonZeroU16::new(dns)
            .filter(|value| value.get() != u16::MAX)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidPortCandidate)?;
        if tcp_echo == dns || udp_echo == dns {
            return Err(ReviewedCanaryFacilityPolicyError::InvalidPortCandidate);
        }
        Ok(Self {
            tcp_echo,
            udp_echo,
            dns,
        })
    }

    #[must_use]
    pub const fn tcp_echo(self) -> NonZeroU16 {
        self.tcp_echo
    }

    #[must_use]
    pub const fn udp_echo(self) -> NonZeroU16 {
        self.udp_echo
    }

    #[must_use]
    pub const fn dns(self) -> NonZeroU16 {
        self.dns
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReviewedCanaryRpdbPolicy {
    proxy_rule_priority: RulePriority,
    peer_rule_priority: RulePriority,
    proxy_capture_table: RouteTableId,
    peer_table: RouteTableId,
    peer_return_table: RouteTableId,
    rule_protocol: NonZeroU8,
    route_protocol: NonZeroU8,
    route_metric: NonZeroU32,
    proxy_mark_value: u32,
    proxy_mark_mask: NonZeroU32,
}

impl ReviewedCanaryRpdbPolicy {
    #[allow(clippy::too_many_arguments)]
    fn new(
        proxy_rule_priority: u32,
        peer_rule_priority: u32,
        default_network_priority: RulePriority,
        proxy_capture_table: u32,
        peer_table: u32,
        peer_return_table: u32,
        rule_protocol: u8,
        route_protocol: u8,
        route_metric: u32,
        proxy_mark_value: u32,
        proxy_mark_mask: u32,
    ) -> Result<Self, ReviewedCanaryFacilityPolicyError> {
        let proxy_rule_priority = RulePriority::from_raw(proxy_rule_priority);
        let peer_rule_priority = RulePriority::from_raw(peer_rule_priority);
        let proxy_capture_table = RouteTableId::from_raw(proxy_capture_table);
        let peer_table = RouteTableId::from_raw(peer_table);
        let peer_return_table = RouteTableId::from_raw(peer_return_table);
        let rule_protocol = NonZeroU8::new(rule_protocol)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidRoutingPolicy)?;
        let route_protocol = NonZeroU8::new(route_protocol)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidRoutingPolicy)?;
        let route_metric = NonZeroU32::new(route_metric)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidRoutingPolicy)?;
        let proxy_mark_mask = NonZeroU32::new(proxy_mark_mask)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidRoutingPolicy)?;
        if proxy_rule_priority.get() == 0
            || proxy_rule_priority >= peer_rule_priority
            || peer_rule_priority >= default_network_priority
            || [0, 253, 254, 255].contains(&proxy_capture_table.get())
            || [0, 253, 254, 255].contains(&peer_table.get())
            || proxy_capture_table == peer_table
            || peer_return_table.get() == 0
            || proxy_mark_value & proxy_mark_mask.get() == 0
            || proxy_mark_value & !proxy_mark_mask.get() != 0
        {
            return Err(ReviewedCanaryFacilityPolicyError::InvalidRoutingPolicy);
        }
        Ok(Self {
            proxy_rule_priority,
            peer_rule_priority,
            proxy_capture_table,
            peer_table,
            peer_return_table,
            rule_protocol,
            route_protocol,
            route_metric,
            proxy_mark_value,
            proxy_mark_mask,
        })
    }

    #[must_use]
    pub const fn proxy_rule_priority(self) -> RulePriority {
        self.proxy_rule_priority
    }

    #[must_use]
    pub const fn peer_rule_priority(self) -> RulePriority {
        self.peer_rule_priority
    }

    #[must_use]
    pub const fn proxy_capture_table(self) -> RouteTableId {
        self.proxy_capture_table
    }

    #[must_use]
    pub const fn peer_table(self) -> RouteTableId {
        self.peer_table
    }

    #[must_use]
    pub const fn peer_return_table(self) -> RouteTableId {
        self.peer_return_table
    }

    #[must_use]
    pub const fn rule_protocol(self) -> NonZeroU8 {
        self.rule_protocol
    }

    #[must_use]
    pub const fn route_protocol(self) -> NonZeroU8 {
        self.route_protocol
    }

    #[must_use]
    pub const fn route_metric(self) -> NonZeroU32 {
        self.route_metric
    }

    #[must_use]
    pub const fn proxy_mark_value(self) -> u32 {
        self.proxy_mark_value
    }

    #[must_use]
    pub const fn proxy_mark_mask(self) -> NonZeroU32 {
        self.proxy_mark_mask
    }
}

/// Exact compiled policy authority required before the native daemon may create a boot facility.
///
/// Live negative observation never constructs this value. The reviewed Android platform catalog
/// is its only positive constructor; the live creator must additionally prove every candidate and
/// kernel object collision-free in the current boot and network namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedCanaryFacilityPolicy {
    catalog_entry: ReviewedPolicyCatalogEntryId,
    revision: NonZeroU64,
    artifact_digest: Sha256Digest,
    daemon_veth_name: InterfaceName,
    peer_veth_name: InterfaceName,
    credentials: ReviewedCanaryRoleCredentials,
    addresses: Box<[ReviewedCanaryFacilityAddressCandidate]>,
    ports: Box<[ReviewedCanaryResponderPortCandidate]>,
    netd_source_profile: AndroidNetdSourceProfile,
    early_uid_lookup_priorities: Box<[RulePriority]>,
    rpdb: ReviewedCanaryRpdbPolicy,
}

/// One exact live address/port choice proven to belong to a reviewed facility pool.
///
/// The value carries no kernel-mutation authority. It only lets the Android RPDB classifier
/// recognize the complete policy-owned peer-rule cohort after the native creator has read it back.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReviewedCanaryFacilitySelection {
    peer_ipv4: Ipv4Addr,
    peer_ipv6: Option<Ipv6Addr>,
    tcp_echo: NonZeroU16,
    udp_echo: NonZeroU16,
    dns: NonZeroU16,
}

impl ReviewedCanaryFacilitySelection {
    #[must_use]
    pub const fn peer_ipv4(self) -> Ipv4Addr {
        self.peer_ipv4
    }

    #[must_use]
    pub const fn peer_ipv6(self) -> Option<Ipv6Addr> {
        self.peer_ipv6
    }

    #[must_use]
    pub const fn tcp_echo(self) -> NonZeroU16 {
        self.tcp_echo
    }

    #[must_use]
    pub const fn udp_echo(self) -> NonZeroU16 {
        self.udp_echo
    }

    #[must_use]
    pub const fn dns(self) -> NonZeroU16 {
        self.dns
    }
}

impl ReviewedCanaryFacilityPolicy {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reviewed(
        catalog_entry: ReviewedPolicyCatalogEntryId,
        revision: u64,
        artifact_digest: [u8; 32],
        daemon_veth_name: &[u8],
        peer_veth_name: &[u8],
        probe_uid: u32,
        probe_gid: u32,
        engine_uid: u32,
        engine_gid: u32,
        addresses: impl IntoIterator<Item = (Ipv4Addr, Ipv4Addr, Option<Ipv6Addr>, Option<Ipv6Addr>)>,
        ports: impl IntoIterator<Item = (u16, u16, u16)>,
        netd_source_profile: AndroidNetdSourceProfile,
        early_uid_lookup_priorities: impl IntoIterator<Item = u32>,
        proxy_rule_priority: u32,
        peer_rule_priority: u32,
        proxy_capture_table: u32,
        peer_table: u32,
        peer_return_table: u32,
        rule_protocol: u8,
        route_protocol: u8,
        route_metric: u32,
        proxy_mark_value: u32,
        proxy_mark_mask: u32,
    ) -> Result<Self, ReviewedCanaryFacilityPolicyError> {
        let revision =
            NonZeroU64::new(revision).ok_or(ReviewedCanaryFacilityPolicyError::InvalidRevision)?;
        let artifact_digest = Sha256Digest::new(artifact_digest)
            .map_err(|_| ReviewedCanaryFacilityPolicyError::InvalidArtifactDigest)?;
        let daemon_veth_name = InterfaceName::new(daemon_veth_name)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidInterfaceNames)?;
        let peer_veth_name = InterfaceName::new(peer_veth_name)
            .ok_or(ReviewedCanaryFacilityPolicyError::InvalidInterfaceNames)?;
        if daemon_veth_name == peer_veth_name {
            return Err(ReviewedCanaryFacilityPolicyError::InvalidInterfaceNames);
        }
        let credentials =
            ReviewedCanaryRoleCredentials::new(probe_uid, probe_gid, engine_uid, engine_gid)?;
        let addresses = addresses
            .into_iter()
            .map(|(daemon_v4, peer_v4, daemon_v6, peer_v6)| {
                ReviewedCanaryFacilityAddressCandidate::new(daemon_v4, peer_v4, daemon_v6, peer_v6)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if addresses.is_empty()
            || addresses.len() > MAX_REVIEWED_CANARY_FACILITY_ADDRESS_CANDIDATES
            || address_candidates_overlap(&addresses)
        {
            return Err(ReviewedCanaryFacilityPolicyError::InvalidAddressPool);
        }
        let ports = ports
            .into_iter()
            .map(|(tcp, udp, dns)| ReviewedCanaryResponderPortCandidate::new(tcp, udp, dns))
            .collect::<Result<Vec<_>, _>>()?;
        if ports.is_empty()
            || ports.len() > MAX_REVIEWED_CANARY_FACILITY_PORT_CANDIDATES
            || port_candidates_overlap(&ports)
        {
            return Err(ReviewedCanaryFacilityPolicyError::InvalidPortPool);
        }
        let rpdb = ReviewedCanaryRpdbPolicy::new(
            proxy_rule_priority,
            peer_rule_priority,
            netd_source_profile.priority_contract().default_network(),
            proxy_capture_table,
            peer_table,
            peer_return_table,
            rule_protocol,
            route_protocol,
            route_metric,
            proxy_mark_value,
            proxy_mark_mask,
        )?;
        let early_uid_lookup_priorities = early_uid_lookup_priorities
            .into_iter()
            .map(RulePriority::from_raw)
            .collect::<Vec<_>>();
        if early_uid_lookup_priorities.len() > MAX_REVIEWED_CANARY_EARLY_UID_LOOKUP_PRIORITIES
            || early_uid_lookup_priorities
                .iter()
                .any(|priority| priority.get() == 0 || *priority >= rpdb.proxy_rule_priority())
            || early_uid_lookup_priorities
                .windows(2)
                .any(|window| window[0] >= window[1])
        {
            return Err(ReviewedCanaryFacilityPolicyError::InvalidRoutingPolicy);
        }
        Ok(Self {
            catalog_entry,
            revision,
            artifact_digest,
            daemon_veth_name,
            peer_veth_name,
            credentials,
            addresses: addresses.into_boxed_slice(),
            ports: ports.into_boxed_slice(),
            netd_source_profile,
            early_uid_lookup_priorities: early_uid_lookup_priorities.into_boxed_slice(),
            rpdb,
        })
    }

    #[must_use]
    pub const fn catalog_entry(&self) -> &ReviewedPolicyCatalogEntryId {
        &self.catalog_entry
    }

    #[must_use]
    pub const fn revision(&self) -> NonZeroU64 {
        self.revision
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> Sha256Digest {
        self.artifact_digest
    }

    #[must_use]
    pub const fn daemon_veth_name(&self) -> InterfaceName {
        self.daemon_veth_name
    }

    #[must_use]
    pub const fn peer_veth_name(&self) -> InterfaceName {
        self.peer_veth_name
    }

    #[must_use]
    pub const fn credentials(&self) -> ReviewedCanaryRoleCredentials {
        self.credentials
    }

    #[must_use]
    pub fn address_candidates(&self) -> &[ReviewedCanaryFacilityAddressCandidate] {
        &self.addresses
    }

    #[must_use]
    pub fn port_candidates(&self) -> &[ReviewedCanaryResponderPortCandidate] {
        &self.ports
    }

    #[must_use]
    pub const fn netd_source_profile(&self) -> AndroidNetdSourceProfile {
        self.netd_source_profile
    }

    /// Exact early priorities at which this reviewed device profile requires one complete IPv4
    /// UID-scoped table lookup. These rules remain Android-first; they are not non-constraining
    /// facility rules and do not grant a generic vendor-rule exception.
    #[must_use]
    pub fn early_uid_lookup_priorities(&self) -> &[RulePriority] {
        &self.early_uid_lookup_priorities
    }

    #[must_use]
    pub const fn rpdb(&self) -> ReviewedCanaryRpdbPolicy {
        self.rpdb
    }

    /// Bind a creator-selected live endpoint only when both choices are exact members of this
    /// compiled reviewed pool.
    pub fn bind_live_selection(
        &self,
        peer_ipv4: Ipv4Addr,
        peer_ipv6: Option<Ipv6Addr>,
        tcp_echo: NonZeroU16,
        udp_echo: NonZeroU16,
        dns: NonZeroU16,
    ) -> Result<ReviewedCanaryFacilitySelection, ReviewedCanaryFacilityPolicyError> {
        let address_is_reviewed = self.addresses.iter().any(|candidate| {
            candidate.peer_ipv4 == peer_ipv4
                && peer_ipv6.is_none_or(|address| candidate.peer_ipv6 == Some(address))
        });
        let ports_are_reviewed = self.ports.iter().any(|candidate| {
            candidate.tcp_echo == tcp_echo && candidate.udp_echo == udp_echo && candidate.dns == dns
        });
        if !address_is_reviewed || !ports_are_reviewed {
            return Err(ReviewedCanaryFacilityPolicyError::UnreviewedLiveSelection);
        }
        Ok(ReviewedCanaryFacilitySelection {
            peer_ipv4,
            peer_ipv6,
            tcp_echo,
            udp_echo,
            dns,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewedCanaryFacilityPolicyError {
    InvalidRevision,
    InvalidArtifactDigest,
    InvalidInterfaceNames,
    InvalidRoleCredentials,
    InvalidAddressCandidate,
    InvalidAddressPool,
    InvalidPortCandidate,
    InvalidPortPool,
    InvalidRoutingPolicy,
    UnreviewedLiveSelection,
}

impl fmt::Display for ReviewedCanaryFacilityPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid reviewed canary facility policy: {self:?}"
        )
    }
}

impl Error for ReviewedCanaryFacilityPolicyError {}

fn address_candidates_overlap(candidates: &[ReviewedCanaryFacilityAddressCandidate]) -> bool {
    for (index, candidate) in candidates.iter().enumerate() {
        let addresses: [Option<IpAddr>; 4] = [
            Some(candidate.daemon_ipv4.into()),
            Some(candidate.peer_ipv4.into()),
            candidate.daemon_ipv6.map(Into::into),
            candidate.peer_ipv6.map(Into::into),
        ];
        for prior in &candidates[..index] {
            let prior_addresses: [Option<IpAddr>; 4] = [
                Some(prior.daemon_ipv4.into()),
                Some(prior.peer_ipv4.into()),
                prior.daemon_ipv6.map(Into::into),
                prior.peer_ipv6.map(Into::into),
            ];
            if addresses.iter().flatten().any(|address| {
                prior_addresses
                    .iter()
                    .flatten()
                    .any(|prior| prior == address)
            }) {
                return true;
            }
        }
    }
    false
}

fn port_candidates_overlap(candidates: &[ReviewedCanaryResponderPortCandidate]) -> bool {
    candidates.iter().enumerate().any(|(index, candidate)| {
        candidates[..index].iter().any(|prior| {
            prior.tcp_echo == candidate.tcp_echo
                || prior.udp_echo == candidate.udp_echo
                || prior.dns == candidate.dns
        })
    })
}

fn ipv4_forbidden(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
}

fn ipv6_forbidden(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_or_shared_role_credentials_cannot_become_reviewed_authority() {
        assert_eq!(
            ReviewedCanaryRoleCredentials::new(0, 0, 0, 0),
            Err(ReviewedCanaryFacilityPolicyError::InvalidRoleCredentials)
        );
        assert_eq!(
            ReviewedCanaryRoleCredentials::new(20_001, 20_001, 20_001, 20_002),
            Err(ReviewedCanaryFacilityPolicyError::InvalidRoleCredentials)
        );
        assert_eq!(
            ReviewedCanaryRoleCredentials::new(20_001, 20_001, 20_002, 20_001),
            Err(ReviewedCanaryFacilityPolicyError::InvalidRoleCredentials)
        );
    }
}
