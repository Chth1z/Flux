use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flux_core::{
    AddressHostFamilySelection, BootIdentity, FluxConfig, InterfaceAddressFlags, InterfaceIndex,
    InterfaceLinkReference, InterfaceName, NetworkAddressFamily, NetworkInventory,
    NetworkNamespaceIdentity, ReviewedCanaryFacilityAddressCandidate, ReviewedCanaryFacilityPolicy,
    ReviewedCanaryFacilitySelection, ReviewedCanaryResponderPortCandidate, RouteFlags, RoutePath,
    RoutePreference, RoutePrefix, RouteProperties, RouteProtocol, RouteScope, RouteTableId,
    RouteType, RuleAction, RuleFlags, RuleFwMark, RuleIpProtocol, RulePortRange, RulePrefix,
    RuleProperties, RuleProtocol, RuleTableId, RuleUidRange,
};
use flux_platform::socket_diagnostics::{
    InetSocketAddressFamily, InetSocketProtocol, ListenerConflictTarget,
    SystemSocketDiagnosticsSource,
};
use flux_platform::{
    NetworkInventorySource, ProcessCredentialMapKind, collect_network_inventory_once,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::functional_canary::{
    ActiveCanaryGenerationBinding, CanaryAddressFamilies, CanaryAttemptCredentialBinding,
    CanaryAttemptObjectIdentities, CanaryAttemptObjectIdentity, CanaryAttemptRequest,
    CanaryAttemptSocketObserverSession, CanaryBindingError, CanaryCleanupStatus,
    CanaryCounterDeltaBounds, CanaryCredentialDomainBinding, CanaryCredentialMapDigest,
    CanaryDeadline, CanaryErrorKind, CanaryFacilityAdmissionObservation,
    CanaryFacilityAdmissionScope, CanaryFacilityAdmissionToken, CanaryFacilityAuditDigest,
    CanaryFacilityIdentity, CanaryFileIdentity, CanaryIpv4AddressPair, CanaryIpv6AddressPair,
    CanaryNonce, CanaryPeerVethTopology, CanaryProcessCredentialIdentity, CanaryResponderPorts,
    CanaryRouteShape, CanaryRpdbIdentity, CanaryVethFamilyTopology, CanaryVethIdentity,
    FunctionalCanaryError,
};
use crate::intent_store::record_io;
use crate::native_runtime_writer::RetainedCanaryFacilityAuthority;
use crate::runtime_coordinator::{
    QualificationCanaryAttemptEnvironmentOwner, QualificationCanaryAttemptEnvironmentSeed,
};

const FACILITY_MUTATION_TIMEOUT: Duration = Duration::from_secs(3);
const FACILITY_INVENTORY_TIMEOUT: Duration = Duration::from_secs(3);
const CREDENTIAL_MAP_MAX_BYTES: usize = 64 * 1024;
const FACILITY_ROUTE_SCOPE_UNIVERSE: u8 = 0;
const FACILITY_ROUTE_SCOPE_LINK: u8 = 253;
const FACILITY_ROUTE_TYPE_UNICAST: u8 = 1;
const FACILITY_ATTEMPT_COUNTER_MAXIMUM: u64 = 128;
const FACILITY_JOURNAL_SCHEMA_VERSION: u16 = 1;
const FACILITY_JOURNAL_MAX_BYTES: usize = 16 * 1024;

#[cfg(any(test, flux_android_qualification))]
const QUALIFICATION_PEER_NETNS_REPORT_MAGIC: &[u8; 8] = b"FLXQ11NS";
#[cfg(any(test, flux_android_qualification))]
const QUALIFICATION_PEER_NETNS_REPORT_VERSION: u16 = 1;
#[cfg(any(test, flux_android_qualification))]
const QUALIFICATION_PEER_NETNS_REPORT_PAYLOAD_LENGTH: u16 = 16;
#[cfg(any(test, flux_android_qualification))]
const QUALIFICATION_PEER_NETNS_REPORT_FRAME_LENGTH: usize = 28;

const FACILITY_POOL_DIGEST_DOMAIN: &[u8] =
    b"Flux reviewed boot canary facility pool\0canonical-v1\0sha256-v1\0";
const FACILITY_AUDIT_DIGEST_DOMAIN: &[u8] =
    b"Flux live boot canary facility audit\0canonical-v1\0sha256-v1\0";
const FACILITY_OBJECT_DIGEST_DOMAIN: &[u8] =
    b"Flux functional canary attempt object\0canonical-v1\0sha256-v1\0";

#[derive(Debug)]
pub(crate) enum NativeCanaryFacilityError {
    Policy(&'static str),
    Binding(CanaryBindingError),
    Platform(Box<str>),
    System {
        operation: &'static str,
        source: io::Error,
    },
    WorkerPanicked(&'static str),
}

impl NativeCanaryFacilityError {
    fn platform(operation: &'static str, error: impl fmt::Display) -> Self {
        Self::Platform(format!("{operation}: {error}").into_boxed_str())
    }

    fn system(operation: &'static str, source: io::Error) -> Self {
        Self::System { operation, source }
    }
}

impl fmt::Display for NativeCanaryFacilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(message) => formatter.write_str(message),
            Self::Binding(error) => error.fmt(formatter),
            Self::Platform(message) => formatter.write_str(message),
            Self::System { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::WorkerPanicked(operation) => write!(formatter, "{operation} worker panicked"),
        }
    }
}

impl Error for NativeCanaryFacilityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Binding(error) => Some(error),
            Self::System { source, .. } => Some(source),
            Self::Policy(_) | Self::Platform(_) | Self::WorkerPanicked(_) => None,
        }
    }
}

impl From<CanaryBindingError> for NativeCanaryFacilityError {
    fn from(error: CanaryBindingError) -> Self {
        Self::Binding(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectedFacilityCandidate {
    addresses: ReviewedCanaryFacilityAddressCandidate,
    ports: ReviewedCanaryResponderPortCandidate,
    families: CanaryAddressFamilies,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCanaryFacilityJournalRecord {
    schema_version: u16,
    boot_identity: String,
    daemon_network_namespace_device: u64,
    daemon_network_namespace_inode: u64,
    reviewed_policy_digest: [u8; 32],
    reviewed_policy_revision: u64,
    daemon_veth_name: Vec<u8>,
    peer_veth_name: Vec<u8>,
    daemon_ipv4: [u8; 4],
    peer_ipv4: [u8; 4],
    daemon_ipv6: Option<[u8; 16]>,
    peer_ipv6: Option<[u8; 16]>,
    tcp_echo_port: u16,
    udp_echo_port: u16,
    dns_port: u16,
    engine_uid: u32,
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
}

pub(crate) struct NativeBootCanaryFacility {
    facility: CanaryFacilityIdentity,
    rpdb: CanaryRpdbIdentity,
    credentials: CanaryAttemptCredentialBinding,
    credential_domain: CanaryCredentialDomainBinding,
    peer_network_namespace: NetworkNamespaceIdentity,
    cleanup: NativeCanaryFacilityCleanup,
    peer_network_namespace_handle: File,
    observation_peer_network_namespace_handle: File,
    reviewed_pool_identity: CanaryFacilityAuditDigest,
    facility_digest: CanaryFacilityAuditDigest,
    families: CanaryAddressFamilies,
    daemon_network_namespace: NetworkNamespaceIdentity,
    reviewed_policy: ReviewedCanaryFacilityPolicy,
    reviewed_selection: ReviewedCanaryFacilitySelection,
}

impl NativeBootCanaryFacility {
    #[cfg(flux_android_qualification)]
    pub(crate) fn report_qualification_peer_network_namespace(
        &self,
        descriptor: OwnedFd,
    ) -> Result<(), NativeCanaryFacilityError> {
        write_qualification_peer_netns_report(descriptor, self.peer_network_namespace)
    }

    pub(crate) fn into_runtime_authorities(
        self,
        inventory: NetworkInventorySource,
    ) -> Result<NativeCanaryRuntimeAuthorities, NativeCanaryFacilityError> {
        let Self {
            facility,
            rpdb,
            credentials,
            credential_domain,
            peer_network_namespace,
            peer_network_namespace_handle,
            observation_peer_network_namespace_handle,
            reviewed_pool_identity,
            facility_digest,
            families,
            daemon_network_namespace,
            reviewed_policy,
            reviewed_selection,
            cleanup,
        } = self;
        let writer = RetainedCanaryFacilityAuthority::new_with_cleanup(
            facility,
            peer_network_namespace,
            peer_network_namespace_handle,
            cleanup,
        )
        .map_err(|error| {
            NativeCanaryFacilityError::platform("retain writer canary facility authority", error)
        })?;
        Ok(NativeCanaryRuntimeAuthorities {
            facility,
            reviewed_policy,
            reviewed_selection,
            environment_owner: Box::new(NativeCanaryEnvironmentOwner {
                facility,
                rpdb,
                credentials,
                credential_domain,
                daemon_network_namespace,
                peer_network_namespace,
                peer_network_namespace_handle: observation_peer_network_namespace_handle,
                reviewed_pool_identity,
                facility_digest,
                families,
                inventory,
                collision_audit_revision: 0,
            }),
            writer,
        })
    }
}

pub(crate) struct NativeCanaryRuntimeAuthorities {
    pub(crate) facility: CanaryFacilityIdentity,
    pub(crate) reviewed_policy: ReviewedCanaryFacilityPolicy,
    pub(crate) reviewed_selection: ReviewedCanaryFacilitySelection,
    pub(crate) environment_owner: Box<dyn QualificationCanaryAttemptEnvironmentOwner>,
    pub(crate) writer: RetainedCanaryFacilityAuthority,
}

pub(crate) struct NativeCanaryEnvironmentOwner {
    facility: CanaryFacilityIdentity,
    rpdb: CanaryRpdbIdentity,
    credentials: CanaryAttemptCredentialBinding,
    credential_domain: CanaryCredentialDomainBinding,
    daemon_network_namespace: NetworkNamespaceIdentity,
    peer_network_namespace: NetworkNamespaceIdentity,
    peer_network_namespace_handle: File,
    reviewed_pool_identity: CanaryFacilityAuditDigest,
    facility_digest: CanaryFacilityAuditDigest,
    families: CanaryAddressFamilies,
    inventory: NetworkInventorySource,
    collision_audit_revision: u64,
}

impl QualificationCanaryAttemptEnvironmentOwner for NativeCanaryEnvironmentOwner {
    fn prepare_environment(
        &mut self,
        generation: &ActiveCanaryGenerationBinding,
        nonce: CanaryNonce,
        deadline: CanaryDeadline,
    ) -> Result<QualificationCanaryAttemptEnvironmentSeed, FunctionalCanaryError> {
        let audit_revision = self
            .collision_audit_revision
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or_else(|| {
                native_environment_error(
                    CanaryErrorKind::AdapterFailure,
                    "canary facility collision-audit revision exhausted",
                )
            })?;
        let daemon_inventory = self
            .validate_live_environment(generation)
            .map_err(native_environment_identity_error)?;
        if !listener_ports_are_clear_values(self.facility.ports(), self.families)
            .map_err(native_environment_adapter_error)?
            || !listener_ports_are_clear_in_namespace_values(
                &self.peer_network_namespace_handle,
                self.facility.ports(),
                self.families,
            )
            .map_err(native_environment_adapter_error)?
        {
            return Err(native_environment_error(
                CanaryErrorKind::IdentityChanged,
                "retained canary responder ports collided during attempt admission",
            ));
        }
        let collision_digest = current_collision_audit_digest(
            self.facility,
            self.rpdb,
            self.credentials,
            self.peer_network_namespace,
            self.facility_digest,
            self.reviewed_pool_identity,
            audit_revision,
            daemon_inventory.as_ref(),
        )
        .map_err(native_environment_identity_error)?;
        let attempt_objects = derive_attempt_object_identities(
            generation.generation(),
            nonce,
            self.facility_digest,
            audit_revision,
        )
        .map_err(native_environment_identity_error)?;
        let socket_observer = CanaryAttemptSocketObserverSession::open_proc_fd_inet_diag(
            attempt_objects.listener_delivery_report(),
            audit_revision,
            deadline,
        )
        .map_err(|error| {
            native_environment_error(
                CanaryErrorKind::AdapterFailure,
                &format!("open canary socket observer: {error}"),
            )
        })?;
        let minimum = match self.families {
            CanaryAddressFamilies::Ipv4Only => 4,
            CanaryAddressFamilies::Ipv4AndIpv6 => 8,
        };
        let counter_bounds = CanaryCounterDeltaBounds::new(
            NonZeroU64::new(minimum).expect("required canary flow count is nonzero"),
            NonZeroU64::new(FACILITY_ATTEMPT_COUNTER_MAXIMUM)
                .expect("canary counter maximum is nonzero"),
            NonZeroU64::new(minimum).expect("required canary flow count is nonzero"),
            NonZeroU64::new(FACILITY_ATTEMPT_COUNTER_MAXIMUM)
                .expect("canary counter maximum is nonzero"),
            0,
        )
        .map_err(native_environment_identity_error)?;
        let observed_at = Instant::now();
        if deadline.has_expired(observed_at) {
            return Err(native_environment_error(
                CanaryErrorKind::TimedOut,
                "canary facility admission exhausted the immutable attempt deadline",
            ));
        }
        self.collision_audit_revision = audit_revision.get();
        Ok(QualificationCanaryAttemptEnvironmentSeed::new(
            self.credentials,
            CanaryFacilityAdmissionToken::new(
                CanaryFacilityAdmissionScope::new(
                    generation.generation(),
                    nonce,
                    self.facility,
                    self.facility_digest,
                    self.reviewed_pool_identity,
                ),
                CanaryFacilityAdmissionObservation::new(
                    daemon_inventory.epoch(),
                    daemon_inventory.snapshot_id(),
                    audit_revision,
                    collision_digest,
                    observed_at,
                    deadline.expires_at(),
                ),
            ),
            self.rpdb,
            attempt_objects,
            self.peer_network_namespace,
            socket_observer,
            self.families,
            counter_bounds,
        ))
    }

    fn reobserve_environment(
        &mut self,
        request: &CanaryAttemptRequest,
        generation: &ActiveCanaryGenerationBinding,
    ) -> Result<(), FunctionalCanaryError> {
        if !generation.matches_environment(request.pre_binding().environment())
            || request.pre_binding().environment().probe_credentials() != self.credentials.probe()
            || request.pre_binding().environment().engine_credentials() != self.credentials.engine()
            || request.pre_binding().environment().credential_domain() != self.credentials.domain()
            || request.pre_binding().environment().rpdb() != self.rpdb
            || request.pre_binding().environment().facility() != self.facility
            || request.pre_binding().environment().attempt_objects()
                != derive_attempt_object_identities(
                    generation.generation(),
                    request.nonce(),
                    self.facility_digest,
                    NonZeroU64::new(self.collision_audit_revision).ok_or_else(|| {
                        native_environment_error(
                            CanaryErrorKind::IdentityChanged,
                            "canary collision-audit revision was not retained",
                        )
                    })?,
                )
                .map_err(native_environment_identity_error)?
        {
            return Err(native_environment_error(
                CanaryErrorKind::IdentityChanged,
                "qualified canary request substituted retained environment authority",
            ));
        }
        self.validate_live_environment(generation)
            .map_err(native_environment_identity_error)?;
        Ok(())
    }
}

impl NativeCanaryEnvironmentOwner {
    fn validate_live_environment(
        &self,
        generation: &ActiveCanaryGenerationBinding,
    ) -> Result<Arc<NetworkInventory>, NativeCanaryFacilityError> {
        validate_current_network_namespace(self.daemon_network_namespace)?;
        if network_namespace_identity(&self.peer_network_namespace_handle)?
            != self.peer_network_namespace
        {
            return Err(NativeCanaryFacilityError::Policy(
                "retained peer network namespace descriptor changed identity",
            ));
        }
        if observe_current_credential_domain(
            [
                self.credentials.probe().uid().get(),
                self.credentials.engine().uid().get(),
            ],
            [
                self.credentials.probe().gid().get(),
                self.credentials.engine().gid().get(),
            ],
        )? != self.credential_domain
        {
            return Err(NativeCanaryFacilityError::Policy(
                "canary credential namespace or ID-map domain changed",
            ));
        }
        let daemon_inventory =
            self.inventory
                .snapshot()
                .ok_or(NativeCanaryFacilityError::Policy(
                    "current reactor network inventory is unavailable or resynchronizing",
                ))?;
        if daemon_inventory.epoch() != generation.network_epoch()
            || daemon_inventory.snapshot_id() != generation.network_inventory_snapshot_id()
        {
            return Err(NativeCanaryFacilityError::Policy(
                "canary Generation network inventory is stale",
            ));
        }
        let peer_inventory = collect_inventory_in_namespace(&self.peer_network_namespace_handle)?;
        validate_live_facility_identity(
            self.facility,
            self.rpdb,
            self.families,
            daemon_inventory.as_ref(),
            peer_inventory.as_ref(),
        )?;
        Ok(daemon_inventory)
    }
}

fn native_environment_error(kind: CanaryErrorKind, diagnostic: &str) -> FunctionalCanaryError {
    FunctionalCanaryError::new(kind, CanaryCleanupStatus::NotRequired, diagnostic)
}

fn native_environment_identity_error(error: impl fmt::Display) -> FunctionalCanaryError {
    native_environment_error(
        CanaryErrorKind::IdentityChanged,
        &format!("revalidate native canary environment: {error}"),
    )
}

fn native_environment_adapter_error(error: impl fmt::Display) -> FunctionalCanaryError {
    native_environment_error(
        CanaryErrorKind::AdapterFailure,
        &format!("observe native canary environment: {error}"),
    )
}

fn derive_attempt_object_identities(
    generation: flux_core::GenerationId,
    nonce: CanaryNonce,
    facility_digest: CanaryFacilityAuditDigest,
    collision_audit_revision: NonZeroU64,
) -> Result<CanaryAttemptObjectIdentities, NativeCanaryFacilityError> {
    let derive = |role: u8| {
        let mut digest = Sha256::new();
        digest.update(FACILITY_OBJECT_DIGEST_DOMAIN);
        digest.update([role]);
        digest.update(generation.get().to_be_bytes());
        digest.update(nonce.as_bytes());
        digest.update(facility_digest.as_bytes());
        digest.update(collision_audit_revision.get().to_be_bytes());
        CanaryAttemptObjectIdentity::new(digest.finalize().into())
            .map_err(NativeCanaryFacilityError::from)
    };
    CanaryAttemptObjectIdentities::new(generation, nonce, derive(1)?, derive(2)?, derive(3)?)
        .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
fn current_collision_audit_digest(
    facility: CanaryFacilityIdentity,
    rpdb: CanaryRpdbIdentity,
    credentials: CanaryAttemptCredentialBinding,
    peer_network_namespace: NetworkNamespaceIdentity,
    facility_digest: CanaryFacilityAuditDigest,
    reviewed_pool_identity: CanaryFacilityAuditDigest,
    collision_audit_revision: NonZeroU64,
    inventory: &NetworkInventory,
) -> Result<CanaryFacilityAuditDigest, NativeCanaryFacilityError> {
    let mut digest = Sha256::new();
    digest.update(FACILITY_AUDIT_DIGEST_DOMAIN);
    digest.update(b"attempt-admission-v1\0");
    digest.update(facility_digest.as_bytes());
    digest.update(reviewed_pool_identity.as_bytes());
    digest.update(collision_audit_revision.get().to_be_bytes());
    digest.update(inventory.epoch().get().to_be_bytes());
    digest.update(inventory.snapshot_id().get().to_be_bytes());
    digest.update(peer_network_namespace.device().to_be_bytes());
    digest.update(peer_network_namespace.inode().to_be_bytes());
    for value in [
        credentials.probe().uid().get(),
        credentials.probe().gid().get(),
        credentials.engine().uid().get(),
        credentials.engine().gid().get(),
        rpdb.engine_uid().get(),
        rpdb.peer_table().get(),
        rpdb.proxy_capture_table().get(),
        rpdb.peer_rule_priority().get(),
        rpdb.proxy_mark_rule_priority().get(),
        rpdb.proxy_mark_value(),
        rpdb.proxy_mark_mask().get(),
        facility.daemon_veth().interface_index().get(),
        facility.peer_veth().interface_index().get(),
    ] {
        digest.update(value.to_be_bytes());
    }
    digest.update([rpdb.rule_protocol().get()]);
    CanaryFacilityAuditDigest::new(digest.finalize().into()).map_err(Into::into)
}

fn validate_live_facility_identity(
    facility: CanaryFacilityIdentity,
    rpdb: CanaryRpdbIdentity,
    families: CanaryAddressFamilies,
    daemon_inventory: &NetworkInventory,
    peer_inventory: &NetworkInventory,
) -> Result<(), NativeCanaryFacilityError> {
    validate_veth_readback(
        daemon_inventory,
        facility.daemon_veth().interface_name().as_bytes(),
        facility.daemon_veth().interface_index(),
        facility.peer_veth().interface_index(),
    )?;
    validate_veth_readback(
        peer_inventory,
        facility.peer_veth().interface_name().as_bytes(),
        facility.peer_veth().interface_index(),
        facility.daemon_veth().interface_index(),
    )?;
    validate_address_readback(
        daemon_inventory,
        peer_inventory,
        facility.daemon_veth().interface_index(),
        IpAddr::V4(facility.ipv4().daemon()),
        facility
            .ipv6()
            .map(|addresses| IpAddr::V6(addresses.daemon())),
    )?;
    validate_address_readback(
        peer_inventory,
        daemon_inventory,
        facility.peer_veth().interface_index(),
        IpAddr::V4(facility.ipv4().peer()),
        facility
            .ipv6()
            .map(|addresses| IpAddr::V6(addresses.peer())),
    )?;
    let topology = facility.peer_veth_topology();
    let mut daemon_routes = vec![facility_route_from_shape(
        IpAddr::V4(facility.ipv4().peer()),
        facility.daemon_veth().interface_index(),
        topology.ipv4().daemon_to_peer_route(),
    )];
    let mut peer_routes = vec![facility_route_from_shape(
        IpAddr::V4(facility.ipv4().daemon()),
        facility.peer_veth().interface_index(),
        topology.ipv4().peer_to_daemon_route(),
    )];
    match (families, facility.ipv6(), topology.ipv6()) {
        (CanaryAddressFamilies::Ipv4Only, None, None) => {}
        (CanaryAddressFamilies::Ipv4AndIpv6, Some(addresses), Some(ipv6)) => {
            daemon_routes.push(facility_route_from_shape(
                IpAddr::V6(addresses.peer()),
                facility.daemon_veth().interface_index(),
                ipv6.daemon_to_peer_route(),
            ));
            peer_routes.push(facility_route_from_shape(
                IpAddr::V6(addresses.daemon()),
                facility.peer_veth().interface_index(),
                ipv6.peer_to_daemon_route(),
            ));
        }
        _ => {
            return Err(NativeCanaryFacilityError::Policy(
                "retained canary address-family topology changed",
            ));
        }
    }
    validate_route_readback("retained daemon", daemon_inventory, &daemon_routes)?;
    validate_route_readback("retained peer", peer_inventory, &peer_routes)?;
    validate_rule_readback(
        daemon_inventory,
        &facility_peer_rules_from_identity(facility, rpdb, families),
    )
}

fn facility_route_from_shape(
    destination: IpAddr,
    output_interface: InterfaceIndex,
    shape: CanaryRouteShape,
) -> FacilityHostRoute {
    FacilityHostRoute {
        destination,
        output_interface,
        table: shape.table(),
        protocol: shape.protocol(),
        scope: shape.scope(),
        metric: shape.metric(),
    }
}

fn facility_peer_rules_from_identity(
    facility: CanaryFacilityIdentity,
    rpdb: CanaryRpdbIdentity,
    families: CanaryAddressFamilies,
) -> Vec<FacilityPeerRule> {
    let mut rules = Vec::with_capacity(if matches!(families, CanaryAddressFamilies::Ipv4Only) {
        4
    } else {
        8
    });
    let ports = facility.ports();
    for destination in std::iter::once(IpAddr::V4(facility.ipv4().peer())).chain(
        matches!(families, CanaryAddressFamilies::Ipv4AndIpv6)
            .then(|| IpAddr::V6(facility.ipv6().expect("validated IPv6 facility").peer())),
    ) {
        for (transport_protocol, destination_port) in [
            (libc::IPPROTO_TCP as u8, ports.tcp_echo().get()),
            (libc::IPPROTO_UDP as u8, ports.udp_echo().get()),
            (libc::IPPROTO_TCP as u8, ports.dns().get()),
            (libc::IPPROTO_UDP as u8, ports.dns().get()),
        ] {
            rules.push(FacilityPeerRule {
                destination,
                engine_uid: rpdb.engine_uid(),
                transport_protocol,
                destination_port,
                priority: rpdb.peer_rule_priority(),
                table: RuleTableId::from_raw(rpdb.peer_table().get()),
                protocol: RuleProtocol::from_raw(rpdb.rule_protocol().get()),
                proxy_mark_mask: rpdb.proxy_mark_mask(),
            });
        }
    }
    rules
}

pub(crate) struct NativeCanaryFacilityCleanup {
    journal_path: PathBuf,
    journal: NativeCanaryFacilityJournalRecord,
    installed_peer_rules: usize,
    active: bool,
}

impl Drop for NativeCanaryFacilityCleanup {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if retire_installed_peer_rules(&self.journal, self.installed_peer_rules).is_ok()
            && cleanup_journaled_facility(&self.journal).is_ok()
            && record_io::remove(&self.journal_path).is_ok()
        {
            self.installed_peer_rules = 0;
            self.active = false;
        }
    }
}

fn retire_installed_peer_rules(
    journal: &NativeCanaryFacilityJournalRecord,
    installed: usize,
) -> Result<(), NativeCanaryFacilityError> {
    let rules = journal_peer_rules(journal)?;
    if installed > rules.len() {
        return Err(NativeCanaryFacilityError::Policy(
            "installed canary peer-rule count exceeds the journaled cohort",
        ));
    }
    for rule in rules[..installed].iter().rev() {
        mutate_peer_rule(*rule, false)?;
    }
    Ok(())
}

fn facility_journal_record(
    policy: &ReviewedCanaryFacilityPolicy,
    selected: SelectedFacilityCandidate,
    boot_identity: &BootIdentity,
    daemon_network_namespace: NetworkNamespaceIdentity,
) -> NativeCanaryFacilityJournalRecord {
    let rpdb = policy.rpdb();
    NativeCanaryFacilityJournalRecord {
        schema_version: FACILITY_JOURNAL_SCHEMA_VERSION,
        boot_identity: boot_identity.as_str().to_owned(),
        daemon_network_namespace_device: daemon_network_namespace.device(),
        daemon_network_namespace_inode: daemon_network_namespace.inode(),
        reviewed_policy_digest: *policy.artifact_digest().as_bytes(),
        reviewed_policy_revision: policy.revision().get(),
        daemon_veth_name: policy.daemon_veth_name().as_bytes().to_vec(),
        peer_veth_name: policy.peer_veth_name().as_bytes().to_vec(),
        daemon_ipv4: selected.addresses.daemon_ipv4().octets(),
        peer_ipv4: selected.addresses.peer_ipv4().octets(),
        daemon_ipv6: matches!(selected.families, CanaryAddressFamilies::Ipv4AndIpv6).then(|| {
            selected
                .addresses
                .daemon_ipv6()
                .expect("dual-stack selection retains daemon IPv6")
                .octets()
        }),
        peer_ipv6: matches!(selected.families, CanaryAddressFamilies::Ipv4AndIpv6).then(|| {
            selected
                .addresses
                .peer_ipv6()
                .expect("dual-stack selection retains peer IPv6")
                .octets()
        }),
        tcp_echo_port: selected.ports.tcp_echo().get(),
        udp_echo_port: selected.ports.udp_echo().get(),
        dns_port: selected.ports.dns().get(),
        engine_uid: policy.credentials().engine_uid().get(),
        proxy_rule_priority: rpdb.proxy_rule_priority().get(),
        peer_rule_priority: rpdb.peer_rule_priority().get(),
        proxy_capture_table: rpdb.proxy_capture_table().get(),
        peer_table: rpdb.peer_table().get(),
        peer_return_table: rpdb.peer_return_table().get(),
        rule_protocol: rpdb.rule_protocol().get(),
        route_protocol: rpdb.route_protocol().get(),
        route_metric: rpdb.route_metric().get(),
        proxy_mark_value: rpdb.proxy_mark_value(),
        proxy_mark_mask: rpdb.proxy_mark_mask().get(),
    }
}

fn persist_facility_journal(
    path: &Path,
    journal: &NativeCanaryFacilityJournalRecord,
) -> Result<(), NativeCanaryFacilityError> {
    let encoded = serde_json::to_vec(journal).map_err(|error| {
        NativeCanaryFacilityError::platform("encode native canary facility journal", error)
    })?;
    if encoded.len() > FACILITY_JOURNAL_MAX_BYTES {
        return Err(NativeCanaryFacilityError::Policy(
            "native canary facility journal exceeds its bounded schema",
        ));
    }
    record_io::write(path, &encoded).map_err(|error| {
        NativeCanaryFacilityError::platform("persist native canary facility journal", error)
    })
}

pub(crate) fn recover_native_boot_canary_facility(
    journal_path: &Path,
    current_boot: &BootIdentity,
    current_network_namespace: NetworkNamespaceIdentity,
) -> Result<(), NativeCanaryFacilityError> {
    let Some(encoded) =
        record_io::read(journal_path, FACILITY_JOURNAL_MAX_BYTES).map_err(|error| {
            NativeCanaryFacilityError::platform("read native canary facility journal", error)
        })?
    else {
        return Ok(());
    };
    let journal: NativeCanaryFacilityJournalRecord =
        serde_json::from_slice(&encoded).map_err(|error| {
            NativeCanaryFacilityError::platform("decode native canary facility journal", error)
        })?;
    validate_facility_journal(&journal)?;
    let same_owner_domain = journal.boot_identity == current_boot.as_str()
        && journal.daemon_network_namespace_device == current_network_namespace.device()
        && journal.daemon_network_namespace_inode == current_network_namespace.inode();
    if same_owner_domain {
        cleanup_journaled_facility(&journal)?;
    } else {
        verify_native_facility_absent(&journal)?;
    }
    record_io::remove(journal_path).map_err(|error| {
        NativeCanaryFacilityError::platform("retire native canary facility journal", error)
    })?;
    Ok(())
}

fn validate_facility_journal(
    journal: &NativeCanaryFacilityJournalRecord,
) -> Result<(), NativeCanaryFacilityError> {
    let daemon_name = InterfaceName::new(&journal.daemon_veth_name);
    let peer_name = InterfaceName::new(&journal.peer_veth_name);
    let boot = BootIdentity::parse(&journal.boot_identity);
    let namespace = NetworkNamespaceIdentity::new(
        journal.daemon_network_namespace_device,
        journal.daemon_network_namespace_inode,
    );
    let credentials = NonZeroU32::new(journal.engine_uid);
    let metric = NonZeroU32::new(journal.route_metric);
    let mask = NonZeroU32::new(journal.proxy_mark_mask);
    if journal.schema_version != FACILITY_JOURNAL_SCHEMA_VERSION
        || daemon_name.is_none()
        || peer_name.is_none()
        || daemon_name == peer_name
        || boot.is_err()
        || namespace.is_none()
        || journal.reviewed_policy_digest.iter().all(|byte| *byte == 0)
        || journal.reviewed_policy_revision == 0
        || credentials.is_none()
        || metric.is_none()
        || mask.is_none()
        || journal.rule_protocol == 0
        || journal.route_protocol == 0
        || journal.proxy_rule_priority == 0
        || journal.proxy_rule_priority >= journal.peer_rule_priority
        || journal.proxy_capture_table == 0
        || journal.peer_table == 0
        || journal.proxy_capture_table == journal.peer_table
        || journal.proxy_mark_value & journal.proxy_mark_mask == 0
        || journal.proxy_mark_value & !journal.proxy_mark_mask != 0
        || journal.daemon_ipv4 == journal.peer_ipv4
        || journal.daemon_ipv6.is_some() != journal.peer_ipv6.is_some()
        || journal
            .daemon_ipv6
            .is_some_and(|address| journal.peer_ipv6 == Some(address))
        || [journal.tcp_echo_port, journal.dns_port].contains(&0)
        || [journal.udp_echo_port, journal.dns_port].contains(&0)
        || journal.tcp_echo_port == journal.dns_port
        || journal.udp_echo_port == journal.dns_port
    {
        return Err(NativeCanaryFacilityError::Policy(
            "native canary facility journal is invalid or noncanonical",
        ));
    }
    journal_peer_rules(journal)?;
    Ok(())
}

fn journal_peer_rules(
    journal: &NativeCanaryFacilityJournalRecord,
) -> Result<Vec<FacilityPeerRule>, NativeCanaryFacilityError> {
    let engine_uid = NonZeroU32::new(journal.engine_uid).ok_or(
        NativeCanaryFacilityError::Policy("journaled canary engine UID is zero"),
    )?;
    let proxy_mark_mask = NonZeroU32::new(journal.proxy_mark_mask).ok_or(
        NativeCanaryFacilityError::Policy("journaled canary proxy mask is zero"),
    )?;
    let mut rules = Vec::with_capacity(if journal.peer_ipv6.is_some() { 8 } else { 4 });
    for destination in std::iter::once(IpAddr::V4(Ipv4Addr::from(journal.peer_ipv4))).chain(
        journal
            .peer_ipv6
            .map(|address| IpAddr::V6(Ipv6Addr::from(address))),
    ) {
        for (transport_protocol, destination_port) in [
            (libc::IPPROTO_TCP as u8, journal.tcp_echo_port),
            (libc::IPPROTO_UDP as u8, journal.udp_echo_port),
            (libc::IPPROTO_TCP as u8, journal.dns_port),
            (libc::IPPROTO_UDP as u8, journal.dns_port),
        ] {
            rules.push(FacilityPeerRule {
                destination,
                engine_uid,
                transport_protocol,
                destination_port,
                priority: flux_core::RulePriority::from_raw(journal.peer_rule_priority),
                table: RuleTableId::from_raw(journal.peer_table),
                protocol: RuleProtocol::from_raw(journal.rule_protocol),
                proxy_mark_mask,
            });
        }
    }
    for rule in &rules {
        expected_rule_record(*rule)?;
    }
    Ok(rules)
}

fn cleanup_journaled_facility(
    journal: &NativeCanaryFacilityJournalRecord,
) -> Result<(), NativeCanaryFacilityError> {
    let inventory =
        collect_network_inventory_once(FACILITY_INVENTORY_TIMEOUT).map_err(|error| {
            NativeCanaryFacilityError::platform("audit journaled canary facility cleanup", error)
        })?;
    let expected_rules = journal_peer_rules(journal)?;
    let actual_rules = inventory
        .rules()
        .iter()
        .filter(|rule| {
            rule.priority().get() == journal.peer_rule_priority
                || rule.properties().table().get() == journal.peer_table
        })
        .collect::<Vec<_>>();
    if actual_rules.iter().any(|actual| {
        !expected_rules
            .iter()
            .filter_map(|rule| expected_rule_record(*rule).ok())
            .any(|expected| **actual == expected)
    }) || expected_rules.iter().any(|expected| {
        let Ok(expected) = expected_rule_record(*expected) else {
            return true;
        };
        actual_rules
            .iter()
            .filter(|actual| ***actual == expected)
            .count()
            > 1
    }) {
        return Err(NativeCanaryFacilityError::Policy(
            "journaled canary rule cohort contains unowned or duplicate rules",
        ));
    }
    for rule in expected_rules.iter().rev() {
        let expected = expected_rule_record(*rule)?;
        if actual_rules.iter().any(|actual| **actual == expected) {
            mutate_peer_rule(*rule, false)?;
        }
    }

    let mut links = inventory
        .links()
        .iter()
        .filter(|link| link.name().as_bytes() == journal.daemon_veth_name);
    if let Some(link) = links.next() {
        if links.next().is_some() || !journaled_daemon_link_matches(journal, link, &inventory)? {
            return Err(NativeCanaryFacilityError::Policy(
                "journaled canary veth cannot be proven as the exact owned link",
            ));
        }
        delete_link(link.interface_index())?;
    } else if journaled_daemon_residue_exists(journal, &inventory) {
        return Err(NativeCanaryFacilityError::Policy(
            "journaled canary link is absent but its address or route remains",
        ));
    }
    verify_native_facility_absent(journal)
}

fn journaled_daemon_link_matches(
    journal: &NativeCanaryFacilityJournalRecord,
    link: &flux_core::InterfaceLinkRecord,
    inventory: &NetworkInventory,
) -> Result<bool, NativeCanaryFacilityError> {
    if link.kind().map(|kind| kind.as_bytes()) != Some(b"veth".as_slice())
        || !matches!(
            link.link_reference(),
            Some(InterfaceLinkReference::Interface(_))
        )
    {
        return Ok(false);
    }
    let index = link.interface_index();
    let expected_ipv4 = IpAddr::V4(Ipv4Addr::from(journal.daemon_ipv4));
    let expected_ipv6 = journal
        .daemon_ipv6
        .map(|address| IpAddr::V6(Ipv6Addr::from(address)));
    let mut required_ipv4 = 0_usize;
    let mut required_ipv6 = 0_usize;
    let mut link_local = 0_usize;
    for address in inventory
        .addresses()
        .iter()
        .filter(|address| address.interface_index() == index)
    {
        if address.address() == expected_ipv4
            && address.prefix_length() == 32
            && !address.flags().intersects(
                InterfaceAddressFlags::TENTATIVE
                    | InterfaceAddressFlags::DAD_FAILED
                    | InterfaceAddressFlags::DEPRECATED,
            )
        {
            required_ipv4 += 1;
        } else if expected_ipv6 == Some(address.address())
            && address.prefix_length() == 128
            && !address.flags().intersects(
                InterfaceAddressFlags::TENTATIVE
                    | InterfaceAddressFlags::DAD_FAILED
                    | InterfaceAddressFlags::DEPRECATED,
            )
        {
            required_ipv6 += 1;
        } else if matches!(address.address(), IpAddr::V6(value) if value.segments()[0] & 0xffc0 == 0xfe80)
            && address.prefix_length() == 64
        {
            link_local += 1;
        } else {
            return Ok(false);
        }
    }
    if required_ipv4 != 1 || required_ipv6 != usize::from(expected_ipv6.is_some()) || link_local > 1
    {
        return Ok(false);
    }
    let routes = journaled_daemon_routes(journal, index)?;
    let actual_routes = inventory
        .routes()
        .iter()
        .filter(|route| route.properties().table().get() == journal.peer_table)
        .collect::<Vec<_>>();
    let expected_routes = routes
        .iter()
        .copied()
        .map(expected_route_record)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(actual_routes.len() == expected_routes.len()
        && expected_routes.iter().all(|expected| {
            actual_routes
                .iter()
                .filter(|actual| ***actual == *expected)
                .count()
                == 1
        }))
}

fn journaled_daemon_routes(
    journal: &NativeCanaryFacilityJournalRecord,
    index: InterfaceIndex,
) -> Result<Vec<FacilityHostRoute>, NativeCanaryFacilityError> {
    let metric = NonZeroU32::new(journal.route_metric).ok_or(NativeCanaryFacilityError::Policy(
        "journaled canary route metric is zero",
    ))?;
    let mut routes = vec![FacilityHostRoute {
        destination: IpAddr::V4(Ipv4Addr::from(journal.peer_ipv4)),
        output_interface: index,
        table: RouteTableId::from_raw(journal.peer_table),
        protocol: RouteProtocol::from_raw(journal.route_protocol),
        scope: facility_route_scope(NetworkAddressFamily::Ipv4),
        metric,
    }];
    if let Some(destination) = journal.peer_ipv6 {
        routes.push(FacilityHostRoute {
            destination: IpAddr::V6(Ipv6Addr::from(destination)),
            output_interface: index,
            table: RouteTableId::from_raw(journal.peer_table),
            protocol: RouteProtocol::from_raw(journal.route_protocol),
            scope: facility_route_scope(NetworkAddressFamily::Ipv6),
            metric,
        });
    }
    Ok(routes)
}

fn journaled_daemon_residue_exists(
    journal: &NativeCanaryFacilityJournalRecord,
    inventory: &NetworkInventory,
) -> bool {
    let addresses = [
        Some(IpAddr::V4(Ipv4Addr::from(journal.daemon_ipv4))),
        journal
            .daemon_ipv6
            .map(|address| IpAddr::V6(Ipv6Addr::from(address))),
    ];
    inventory
        .addresses()
        .iter()
        .any(|address| addresses.contains(&Some(address.address())))
        || inventory.routes().iter().any(|route| {
            route.properties().table().get() == journal.peer_table
                && route.properties().protocol().raw() == journal.route_protocol
        })
}

fn verify_native_facility_absent(
    journal: &NativeCanaryFacilityJournalRecord,
) -> Result<(), NativeCanaryFacilityError> {
    let inventory =
        collect_network_inventory_once(FACILITY_INVENTORY_TIMEOUT).map_err(|error| {
            NativeCanaryFacilityError::platform("verify native canary facility absence", error)
        })?;
    let names = [
        journal.daemon_veth_name.as_slice(),
        journal.peer_veth_name.as_slice(),
    ];
    let addresses = [
        Some(IpAddr::V4(Ipv4Addr::from(journal.daemon_ipv4))),
        Some(IpAddr::V4(Ipv4Addr::from(journal.peer_ipv4))),
        journal
            .daemon_ipv6
            .map(|address| IpAddr::V6(Ipv6Addr::from(address))),
        journal
            .peer_ipv6
            .map(|address| IpAddr::V6(Ipv6Addr::from(address))),
    ];
    if inventory
        .links()
        .iter()
        .any(|link| names.contains(&link.name().as_bytes()))
        || inventory
            .addresses()
            .iter()
            .any(|address| addresses.contains(&Some(address.address())))
        || inventory.routes().iter().any(|route| {
            route.properties().table().get() == journal.peer_table
                && route.properties().protocol().raw() == journal.route_protocol
        })
        || inventory.rules().iter().any(|rule| {
            rule.priority().get() == journal.peer_rule_priority
                || rule.properties().table().get() == journal.peer_table
        })
    {
        return Err(NativeCanaryFacilityError::Policy(
            "native canary facility cleanup did not prove exact absence",
        ));
    }
    Ok(())
}

pub(crate) fn create_native_boot_canary_facility(
    policy: &ReviewedCanaryFacilityPolicy,
    config: &FluxConfig,
    boot_identity: &BootIdentity,
    daemon_network_namespace: NetworkNamespaceIdentity,
    pre_mutation_inventory: &Arc<NetworkInventory>,
    journal_path: &Path,
) -> Result<NativeBootCanaryFacility, NativeCanaryFacilityError> {
    validate_current_network_namespace(daemon_network_namespace)?;
    let reviewed_credentials = policy.credentials();
    let credential_domain = observe_current_credential_domain(
        [
            reviewed_credentials.probe_uid().get(),
            reviewed_credentials.engine_uid().get(),
        ],
        [
            reviewed_credentials.probe_gid().get(),
            reviewed_credentials.engine_gid().get(),
        ],
    )?;
    let selected =
        select_facility_candidate(policy, config, pre_mutation_inventory, |ports, families| {
            listener_ports_are_clear(ports, families)
        })?;
    let reviewed_pool_identity = reviewed_pool_identity(policy)?;
    create_selected_native_facility(
        policy,
        selected,
        credential_domain,
        boot_identity,
        daemon_network_namespace,
        pre_mutation_inventory,
        reviewed_pool_identity,
        journal_path,
    )
}

fn select_facility_candidate(
    policy: &ReviewedCanaryFacilityPolicy,
    config: &FluxConfig,
    inventory: &NetworkInventory,
    mut ports_are_clear: impl FnMut(
        ReviewedCanaryResponderPortCandidate,
        CanaryAddressFamilies,
    ) -> Result<bool, NativeCanaryFacilityError>,
) -> Result<SelectedFacilityCandidate, NativeCanaryFacilityError> {
    let reviewed_credentials = policy.credentials();
    let configured_credentials = config.engine().credentials();
    if configured_credentials.uid().get() != reviewed_credentials.engine_uid().get()
        || configured_credentials.gid().get() != reviewed_credentials.engine_gid().get()
    {
        return Err(NativeCanaryFacilityError::Policy(
            "configured engine credentials do not match the reviewed canary role policy",
        ));
    }
    let families = match config.capture().scope().families() {
        AddressHostFamilySelection::Ipv4 => CanaryAddressFamilies::Ipv4Only,
        AddressHostFamilySelection::DualStack => CanaryAddressFamilies::Ipv4AndIpv6,
        AddressHostFamilySelection::Ipv6 => {
            return Err(NativeCanaryFacilityError::Policy(
                "the production functional canary does not support IPv6-only capture",
            ));
        }
    };
    if inventory.links().iter().any(|link| {
        link.name() == &policy.daemon_veth_name() || link.name() == &policy.peer_veth_name()
    }) {
        return Err(NativeCanaryFacilityError::Policy(
            "reviewed canary interface name collides with the live inventory",
        ));
    }
    let rpdb = policy.rpdb();
    if inventory.routes().iter().any(|route| {
        [rpdb.proxy_capture_table().get(), rpdb.peer_table().get()]
            .contains(&route.properties().table().get())
    }) || inventory.rules().iter().any(|rule| {
        rule.priority() == rpdb.proxy_rule_priority()
            || rule.priority() == rpdb.peer_rule_priority()
            || [rpdb.proxy_capture_table().get(), rpdb.peer_table().get()]
                .contains(&rule.properties().table().get())
    }) {
        return Err(NativeCanaryFacilityError::Policy(
            "reviewed canary routing identity collides with the live inventory",
        ));
    }

    let addresses = policy
        .address_candidates()
        .iter()
        .copied()
        .find(|candidate| address_candidate_is_clear(*candidate, families, config, inventory))
        .ok_or(NativeCanaryFacilityError::Policy(
            "no reviewed canary address candidate is collision-free",
        ))?;
    let mut selected_ports = None;
    for ports in policy.port_candidates().iter().copied() {
        if [ports.tcp_echo(), ports.udp_echo(), ports.dns()].contains(&config.listener().port()) {
            continue;
        }
        if ports_are_clear(ports, families)? {
            selected_ports = Some(ports);
            break;
        }
    }
    let ports = selected_ports.ok_or(NativeCanaryFacilityError::Policy(
        "no reviewed canary responder-port candidate is collision-free",
    ))?;
    Ok(SelectedFacilityCandidate {
        addresses,
        ports,
        families,
    })
}

fn address_candidate_is_clear(
    candidate: ReviewedCanaryFacilityAddressCandidate,
    families: CanaryAddressFamilies,
    config: &FluxConfig,
    inventory: &NetworkInventory,
) -> bool {
    let mut addresses = vec![
        IpAddr::V4(candidate.daemon_ipv4()),
        IpAddr::V4(candidate.peer_ipv4()),
    ];
    if matches!(families, CanaryAddressFamilies::Ipv4AndIpv6) {
        let (Some(daemon), Some(peer)) = (candidate.daemon_ipv6(), candidate.peer_ipv6()) else {
            return false;
        };
        addresses.extend([IpAddr::V6(daemon), IpAddr::V6(peer)]);
    }
    addresses.iter().all(|address| {
        !inventory
            .addresses()
            .iter()
            .any(|observed| observed.address() == *address)
            && !inventory.routes().iter().any(|route| {
                (route.destination().prefix_length()
                    == host_prefix_length(route.destination().family())
                    && route.destination().address() == *address)
                    || route_path_uses_gateway(route.path(), *address)
            })
            && !inventory.rules().iter().any(|rule| {
                (rule.destination().prefix_length()
                    == host_prefix_length(rule.destination().family())
                    && rule.destination().address() == *address)
                    || (rule.source().prefix_length() == host_prefix_length(rule.source().family())
                        && rule.source().address() == *address)
            })
            && !config
                .bypass()
                .policy()
                .prefixes()
                .iter()
                .any(|prefix| prefix.contains(*address))
    })
}

fn route_path_uses_gateway(path: &RoutePath, address: IpAddr) -> bool {
    let matches = |gateway: flux_core::RouteGateway| match gateway {
        flux_core::RouteGateway::Direct(observed) | flux_core::RouteGateway::Via(observed) => {
            observed == address
        }
    };
    match path {
        RoutePath::None => false,
        RoutePath::Single { gateway, .. } => gateway.is_some_and(matches),
        RoutePath::Multipath(nexthops) => nexthops
            .iter()
            .any(|nexthop| nexthop.gateway().is_some_and(matches)),
    }
}

const fn host_prefix_length(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 32,
        NetworkAddressFamily::Ipv6 => 128,
    }
}

fn listener_ports_are_clear(
    ports: ReviewedCanaryResponderPortCandidate,
    families: CanaryAddressFamilies,
) -> Result<bool, NativeCanaryFacilityError> {
    let ports = CanaryResponderPorts::new(ports.tcp_echo(), ports.udp_echo(), ports.dns())?;
    listener_ports_are_clear_values(ports, families)
}

fn listener_ports_are_clear_values(
    ports: CanaryResponderPorts,
    families: CanaryAddressFamilies,
) -> Result<bool, NativeCanaryFacilityError> {
    let targets = listener_conflict_targets(ports, families);
    let deadline = Instant::now()
        .checked_add(FACILITY_MUTATION_TIMEOUT)
        .ok_or(NativeCanaryFacilityError::Policy(
            "canary listener-conflict deadline overflowed",
        ))?;
    let session = SystemSocketDiagnosticsSource
        .open_until(deadline)
        .map_err(|error| {
            NativeCanaryFacilityError::platform("open listener collision audit", error)
        })?;
    let (_, snapshot) = session
        .collect_listener_conflicts_until(&targets, deadline)
        .map_err(|error| {
            NativeCanaryFacilityError::platform("collect listener collision audit", error)
        })?;
    Ok(snapshot.conflicts().is_empty())
}

fn listener_conflict_targets(
    ports: CanaryResponderPorts,
    families: CanaryAddressFamilies,
) -> Vec<ListenerConflictTarget> {
    let mut targets = Vec::with_capacity(if matches!(families, CanaryAddressFamilies::Ipv4Only) {
        4
    } else {
        8
    });
    for family in std::iter::once(InetSocketAddressFamily::Ipv4).chain(
        matches!(families, CanaryAddressFamilies::Ipv4AndIpv6)
            .then_some(InetSocketAddressFamily::Ipv6),
    ) {
        targets.extend([
            ListenerConflictTarget::new(family, InetSocketProtocol::Tcp, ports.tcp_echo()),
            ListenerConflictTarget::new(family, InetSocketProtocol::Udp, ports.udp_echo()),
            ListenerConflictTarget::new(family, InetSocketProtocol::Tcp, ports.dns()),
            ListenerConflictTarget::new(family, InetSocketProtocol::Udp, ports.dns()),
        ]);
    }
    targets
}

fn reviewed_pool_identity(
    policy: &ReviewedCanaryFacilityPolicy,
) -> Result<CanaryFacilityAuditDigest, NativeCanaryFacilityError> {
    let mut digest = Sha256::new();
    digest.update(FACILITY_POOL_DIGEST_DOMAIN);
    digest.update(policy.catalog_entry().as_str().as_bytes());
    digest.update(policy.revision().get().to_be_bytes());
    digest.update(policy.artifact_digest().as_bytes());
    digest.update(policy.daemon_veth_name().as_bytes());
    digest.update(policy.peer_veth_name().as_bytes());
    let credentials = policy.credentials();
    for value in [
        credentials.probe_uid().get(),
        credentials.probe_gid().get(),
        credentials.engine_uid().get(),
        credentials.engine_gid().get(),
    ] {
        digest.update(value.to_be_bytes());
    }
    for candidate in policy.address_candidates() {
        digest.update(candidate.daemon_ipv4().octets());
        digest.update(candidate.peer_ipv4().octets());
        digest.update(
            candidate
                .daemon_ipv6()
                .map_or([0; 16], |value| value.octets()),
        );
        digest.update(
            candidate
                .peer_ipv6()
                .map_or([0; 16], |value| value.octets()),
        );
    }
    for candidate in policy.port_candidates() {
        for port in [candidate.tcp_echo(), candidate.udp_echo(), candidate.dns()] {
            digest.update(port.get().to_be_bytes());
        }
    }
    CanaryFacilityAuditDigest::new(digest.finalize().into()).map_err(Into::into)
}

fn observe_current_credential_domain(
    role_uids: [u32; 2],
    role_gids: [u32; 2],
) -> Result<CanaryCredentialDomainBinding, NativeCanaryFacilityError> {
    let first = read_current_credential_domain(role_uids, role_gids)?;
    let second = read_current_credential_domain(role_uids, role_gids)?;
    if first != second {
        return Err(NativeCanaryFacilityError::Policy(
            "daemon credential namespace or ID maps changed during observation",
        ));
    }
    Ok(first)
}

fn read_current_credential_domain(
    role_uids: [u32; 2],
    role_gids: [u32; 2],
) -> Result<CanaryCredentialDomainBinding, NativeCanaryFacilityError> {
    let mount = open_namespace_identity("/proc/self/ns/mnt", "open daemon mount namespace")?;
    let user =
        open_optional_namespace_identity("/proc/self/ns/user", "open daemon user namespace")?;
    let uid_map = read_optional_bounded_file(
        "/proc/self/uid_map",
        CREDENTIAL_MAP_MAX_BYTES,
        "open daemon UID map",
    )?;
    let gid_map = read_optional_bounded_file(
        "/proc/self/gid_map",
        CREDENTIAL_MAP_MAX_BYTES,
        "open daemon GID map",
    )?;
    bind_current_credential_domain(
        user,
        mount,
        uid_map.as_deref(),
        gid_map.as_deref(),
        role_uids,
        role_gids,
    )
}

fn bind_current_credential_domain(
    user: Option<CanaryFileIdentity>,
    mount: CanaryFileIdentity,
    uid_map: Option<&[u8]>,
    gid_map: Option<&[u8]>,
    role_uids: [u32; 2],
    role_gids: [u32; 2],
) -> Result<CanaryCredentialDomainBinding, NativeCanaryFacilityError> {
    let (user, uid_map, gid_map) = match (user, uid_map, gid_map) {
        (None, None, None) => return Ok(CanaryCredentialDomainBinding::unsupported(mount)),
        (Some(user), Some(uid_map), Some(gid_map)) => (user, uid_map, gid_map),
        _ => {
            return Err(NativeCanaryFacilityError::Policy(
                "daemon user namespace and credential maps have incoherent presence",
            ));
        }
    };
    let uid_digest = flux_platform::internal::digest_current_process_id_map(
        uid_map,
        ProcessCredentialMapKind::Uid,
    )
    .map_err(|error| NativeCanaryFacilityError::platform("digest daemon UID map", error))?;
    let gid_digest = flux_platform::internal::digest_current_process_id_map(
        gid_map,
        ProcessCredentialMapKind::Gid,
    )
    .map_err(|error| NativeCanaryFacilityError::platform("digest daemon GID map", error))?;
    for (map, kind, ids) in [
        (uid_map, ProcessCredentialMapKind::Uid, role_uids),
        (gid_map, ProcessCredentialMapKind::Gid, role_gids),
    ] {
        for id in ids {
            if !flux_platform::internal::current_process_id_map_contains(map, kind, id).map_err(
                |error| {
                    NativeCanaryFacilityError::platform("validate daemon credential map", error)
                },
            )? {
                return Err(NativeCanaryFacilityError::Policy(
                    "reviewed canary role credentials are not live in the daemon ID-map domain",
                ));
            }
        }
    }
    CanaryCredentialDomainBinding::observed(
        user,
        mount,
        CanaryCredentialMapDigest::new(*uid_digest.as_bytes())?,
        CanaryCredentialMapDigest::new(*gid_digest.as_bytes())?,
    )
    .map_err(Into::into)
}

fn open_namespace_identity(
    path: &str,
    operation: &'static str,
) -> Result<CanaryFileIdentity, NativeCanaryFacilityError> {
    let file =
        File::open(path).map_err(|source| NativeCanaryFacilityError::system(operation, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| NativeCanaryFacilityError::system(operation, source))?;
    let inode = NonZeroU64::new(metadata.ino()).ok_or(NativeCanaryFacilityError::Policy(
        "namespace descriptor has a zero inode",
    ))?;
    Ok(CanaryFileIdentity::new(metadata.dev(), inode))
}

fn open_optional_namespace_identity(
    path: &str,
    operation: &'static str,
) -> Result<Option<CanaryFileIdentity>, NativeCanaryFacilityError> {
    let Some(file) = open_optional_file(path, operation)? else {
        return Ok(None);
    };
    let metadata = file
        .metadata()
        .map_err(|source| NativeCanaryFacilityError::system(operation, source))?;
    let inode = NonZeroU64::new(metadata.ino()).ok_or(NativeCanaryFacilityError::Policy(
        "namespace descriptor has a zero inode",
    ))?;
    Ok(Some(CanaryFileIdentity::new(metadata.dev(), inode)))
}

fn read_optional_bounded_file(
    path: &str,
    limit: usize,
    operation: &'static str,
) -> Result<Option<Vec<u8>>, NativeCanaryFacilityError> {
    let Some(mut file) = open_optional_file(path, operation)? else {
        return Ok(None);
    };
    let mut contents = Vec::with_capacity(limit.saturating_add(1));
    file.by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|source| NativeCanaryFacilityError::system("read credential map", source))?;
    if contents.len() > limit {
        return Err(NativeCanaryFacilityError::Policy(
            "credential map exceeds the bounded observation limit",
        ));
    }
    Ok(Some(contents))
}

fn open_optional_file(
    path: &str,
    operation: &'static str,
) -> Result<Option<File>, NativeCanaryFacilityError> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(NativeCanaryFacilityError::system(operation, source)),
    }
}

fn validate_current_network_namespace(
    expected: NetworkNamespaceIdentity,
) -> Result<(), NativeCanaryFacilityError> {
    let observed =
        network_namespace_identity(&File::open("/proc/self/ns/net").map_err(|source| {
            NativeCanaryFacilityError::system("open daemon network namespace", source)
        })?)?;
    if observed != expected {
        return Err(NativeCanaryFacilityError::Policy(
            "daemon network namespace changed before boot-facility creation",
        ));
    }
    Ok(())
}

fn network_namespace_identity(
    handle: &File,
) -> Result<NetworkNamespaceIdentity, NativeCanaryFacilityError> {
    let metadata = handle.metadata().map_err(|source| {
        NativeCanaryFacilityError::system("inspect network namespace descriptor", source)
    })?;
    NetworkNamespaceIdentity::new(metadata.dev(), metadata.ino()).ok_or(
        NativeCanaryFacilityError::Policy("network namespace descriptor has a zero inode"),
    )
}

#[cfg(any(test, flux_android_qualification))]
fn encode_qualification_peer_netns_report(
    identity: NetworkNamespaceIdentity,
) -> [u8; QUALIFICATION_PEER_NETNS_REPORT_FRAME_LENGTH] {
    let mut encoded = [0_u8; QUALIFICATION_PEER_NETNS_REPORT_FRAME_LENGTH];
    encoded[..8].copy_from_slice(QUALIFICATION_PEER_NETNS_REPORT_MAGIC);
    encoded[8..10].copy_from_slice(&QUALIFICATION_PEER_NETNS_REPORT_VERSION.to_be_bytes());
    encoded[10..12].copy_from_slice(&QUALIFICATION_PEER_NETNS_REPORT_PAYLOAD_LENGTH.to_be_bytes());
    encoded[12..20].copy_from_slice(&identity.device().to_be_bytes());
    encoded[20..28].copy_from_slice(&identity.inode().to_be_bytes());
    encoded
}

#[cfg(any(test, flux_android_qualification))]
fn write_qualification_peer_netns_report(
    descriptor: OwnedFd,
    identity: NetworkNamespaceIdentity,
) -> Result<(), NativeCanaryFacilityError> {
    let encoded = encode_qualification_peer_netns_report(identity);
    let mut report = File::from(descriptor);
    io::Write::write_all(&mut report, &encoded).map_err(|source| {
        NativeCanaryFacilityError::system(
            "write qualification peer network namespace report",
            source,
        )
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FacilityHostRoute {
    destination: IpAddr,
    output_interface: InterfaceIndex,
    table: RouteTableId,
    protocol: RouteProtocol,
    scope: RouteScope,
    metric: NonZeroU32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FacilityPeerRule {
    destination: IpAddr,
    engine_uid: NonZeroU32,
    transport_protocol: u8,
    destination_port: u16,
    priority: flux_core::RulePriority,
    table: RuleTableId,
    protocol: RuleProtocol,
    proxy_mark_mask: NonZeroU32,
}

#[allow(clippy::too_many_arguments)]
fn create_selected_native_facility(
    policy: &ReviewedCanaryFacilityPolicy,
    selected: SelectedFacilityCandidate,
    credential_domain: CanaryCredentialDomainBinding,
    boot_identity: &BootIdentity,
    daemon_network_namespace: NetworkNamespaceIdentity,
    pre_mutation_inventory: &NetworkInventory,
    reviewed_pool_identity: CanaryFacilityAuditDigest,
    journal_path: &Path,
) -> Result<NativeBootCanaryFacility, NativeCanaryFacilityError> {
    let journal =
        facility_journal_record(policy, selected, boot_identity, daemon_network_namespace);
    persist_facility_journal(journal_path, &journal)?;
    let mut cleanup = NativeCanaryFacilityCleanup {
        journal_path: journal_path.to_owned(),
        journal,
        installed_peer_rules: 0,
        active: true,
    };
    let peer_network_namespace_handle = create_peer_network_namespace()?;
    let peer_network_namespace = network_namespace_identity(&peer_network_namespace_handle)?;
    if peer_network_namespace == daemon_network_namespace {
        return Err(NativeCanaryFacilityError::Policy(
            "peer network namespace creation returned the daemon namespace",
        ));
    }
    let observation_peer_network_namespace_handle = peer_network_namespace_handle
        .try_clone()
        .map_err(|source| {
            NativeCanaryFacilityError::system("duplicate peer network namespace descriptor", source)
        })?;
    create_veth_pair(
        policy.daemon_veth_name().as_bytes(),
        policy.peer_veth_name().as_bytes(),
        peer_network_namespace_handle.as_raw_fd(),
    )?;

    let early_daemon_inventory = collect_network_inventory_once(FACILITY_INVENTORY_TIMEOUT)
        .map_err(|error| {
            NativeCanaryFacilityError::platform("observe newly created daemon veth", error)
        })?;
    let daemon_veth_index = unique_interface_index(
        &early_daemon_inventory,
        policy.daemon_veth_name().as_bytes(),
    )?;
    let early_peer_inventory = collect_inventory_in_namespace(&peer_network_namespace_handle)?;
    let peer_veth_index =
        unique_interface_index(&early_peer_inventory, policy.peer_veth_name().as_bytes())?;

    let daemon_route = facility_host_route(
        IpAddr::V4(selected.addresses.peer_ipv4()),
        daemon_veth_index,
        policy.rpdb().peer_table(),
        policy,
    );
    let peer_route = facility_host_route(
        IpAddr::V4(selected.addresses.daemon_ipv4()),
        peer_veth_index,
        policy.rpdb().peer_return_table(),
        policy,
    );
    let mut daemon_routes = vec![daemon_route];
    let mut peer_routes = vec![peer_route];
    if matches!(selected.families, CanaryAddressFamilies::Ipv4AndIpv6) {
        daemon_routes.push(facility_host_route(
            IpAddr::V6(
                selected
                    .addresses
                    .peer_ipv6()
                    .expect("dual-stack selection retains peer IPv6"),
            ),
            daemon_veth_index,
            policy.rpdb().peer_table(),
            policy,
        ));
        peer_routes.push(facility_host_route(
            IpAddr::V6(
                selected
                    .addresses
                    .daemon_ipv6()
                    .expect("dual-stack selection retains daemon IPv6"),
            ),
            peer_veth_index,
            policy.rpdb().peer_return_table(),
            policy,
        ));
    }
    let rules = facility_peer_rules(policy, selected);

    let setup = (|| {
        set_link_up(daemon_veth_index)?;
        add_interface_address(
            daemon_veth_index,
            IpAddr::V4(selected.addresses.daemon_ipv4()),
        )?;
        if let Some(address) = selected
            .addresses
            .daemon_ipv6()
            .filter(|_| matches!(selected.families, CanaryAddressFamilies::Ipv4AndIpv6))
        {
            add_interface_address(daemon_veth_index, IpAddr::V6(address))?;
        }
        configure_peer_namespace(
            &peer_network_namespace_handle,
            peer_veth_index,
            selected,
            peer_routes.clone(),
        )?;
        // Add daemon-side routes only after the peer link is administratively up. Linux may
        // persist `RTNH_F_LINKDOWN` in a route installed while the veth peer is still down,
        // making exact route readback depend on setup scheduling.
        for route in &daemon_routes {
            mutate_route(*route, true)?;
        }
        Ok::<(), NativeCanaryFacilityError>(())
    })();
    setup?;

    let topology_inventory =
        collect_network_inventory_once(FACILITY_INVENTORY_TIMEOUT).map_err(|error| {
            NativeCanaryFacilityError::platform("read back daemon canary facility", error)
        })?;
    let peer_inventory = collect_inventory_in_namespace(&peer_network_namespace_handle)?;
    validate_created_facility_topology(
        policy,
        selected,
        daemon_veth_index,
        peer_veth_index,
        &daemon_routes,
        &peer_routes,
        &topology_inventory,
        &peer_inventory,
    )?;
    for rule in &rules {
        mutate_peer_rule(*rule, true)?;
        cleanup.installed_peer_rules += 1;
    }
    let daemon_inventory =
        collect_network_inventory_once(FACILITY_INVENTORY_TIMEOUT).map_err(|error| {
            NativeCanaryFacilityError::platform("read back daemon canary RPDB rules", error)
        })?;
    validate_rule_readback(&daemon_inventory, &rules)?;
    if !listener_ports_are_clear_in_namespace(
        &peer_network_namespace_handle,
        selected.ports,
        selected.families,
    )? {
        return Err(NativeCanaryFacilityError::Policy(
            "reviewed responder ports collide inside the new peer namespace",
        ));
    }

    let topology = facility_topology(policy, selected.families)?;
    let facility = CanaryFacilityIdentity::new(
        CanaryVethIdentity::new(daemon_veth_index, policy.daemon_veth_name()),
        CanaryVethIdentity::new(peer_veth_index, policy.peer_veth_name()),
        CanaryIpv4AddressPair::new(
            selected.addresses.daemon_ipv4(),
            selected.addresses.peer_ipv4(),
        )?,
        match selected.families {
            CanaryAddressFamilies::Ipv4Only => None,
            CanaryAddressFamilies::Ipv4AndIpv6 => Some(CanaryIpv6AddressPair::new(
                selected
                    .addresses
                    .daemon_ipv6()
                    .expect("dual-stack selection retains daemon IPv6"),
                selected
                    .addresses
                    .peer_ipv6()
                    .expect("dual-stack selection retains peer IPv6"),
            )?),
        },
        topology,
        CanaryResponderPorts::new(
            selected.ports.tcp_echo(),
            selected.ports.udp_echo(),
            selected.ports.dns(),
        )?,
    )?;
    let reviewed_credentials = policy.credentials();
    let credentials = CanaryAttemptCredentialBinding::new(
        CanaryProcessCredentialIdentity::new(
            reviewed_credentials.probe_uid(),
            reviewed_credentials.probe_gid(),
        ),
        CanaryProcessCredentialIdentity::new(
            reviewed_credentials.engine_uid(),
            reviewed_credentials.engine_gid(),
        ),
        credential_domain,
    )?;
    let rpdb_policy = policy.rpdb();
    let rpdb = CanaryRpdbIdentity::new(
        reviewed_credentials.engine_uid(),
        rpdb_policy.rule_protocol(),
        rpdb_policy.peer_table(),
        rpdb_policy.proxy_capture_table(),
        rpdb_policy.peer_rule_priority(),
        rpdb_policy.proxy_rule_priority(),
        rpdb_policy.proxy_mark_value(),
        rpdb_policy.proxy_mark_mask(),
    )?;
    let facility_digest = live_facility_digest(
        policy,
        selected,
        facility,
        peer_network_namespace,
        pre_mutation_inventory,
        &daemon_inventory,
        &peer_inventory,
    )?;
    let reviewed_selection = policy
        .bind_live_selection(
            selected.addresses.peer_ipv4(),
            match selected.families {
                CanaryAddressFamilies::Ipv4Only => None,
                CanaryAddressFamilies::Ipv4AndIpv6 => selected.addresses.peer_ipv6(),
            },
            selected.ports.tcp_echo(),
            selected.ports.udp_echo(),
            selected.ports.dns(),
        )
        .map_err(|error| {
            NativeCanaryFacilityError::platform("bind reviewed live canary selection", error)
        })?;
    Ok(NativeBootCanaryFacility {
        facility,
        rpdb,
        credentials,
        credential_domain,
        peer_network_namespace,
        peer_network_namespace_handle,
        observation_peer_network_namespace_handle,
        reviewed_pool_identity,
        facility_digest,
        families: selected.families,
        daemon_network_namespace,
        reviewed_policy: policy.clone(),
        reviewed_selection,
        cleanup,
    })
}

fn facility_topology(
    policy: &ReviewedCanaryFacilityPolicy,
    families: CanaryAddressFamilies,
) -> Result<CanaryPeerVethTopology, NativeCanaryFacilityError> {
    let ipv4_daemon_shape = CanaryRouteShape::new(
        policy.rpdb().peer_table(),
        RouteProtocol::from_raw(policy.rpdb().route_protocol().get()),
        facility_route_scope(NetworkAddressFamily::Ipv4),
        policy.rpdb().route_metric(),
    )?;
    let ipv4_peer_shape = CanaryRouteShape::new(
        policy.rpdb().peer_return_table(),
        RouteProtocol::from_raw(policy.rpdb().route_protocol().get()),
        facility_route_scope(NetworkAddressFamily::Ipv4),
        policy.rpdb().route_metric(),
    )?;
    let ipv4 = CanaryVethFamilyTopology::ipv4(32, 32, ipv4_daemon_shape, ipv4_peer_shape)?;
    let ipv6 = matches!(families, CanaryAddressFamilies::Ipv4AndIpv6)
        .then(|| {
            let daemon_shape = CanaryRouteShape::new(
                policy.rpdb().peer_table(),
                RouteProtocol::from_raw(policy.rpdb().route_protocol().get()),
                facility_route_scope(NetworkAddressFamily::Ipv6),
                policy.rpdb().route_metric(),
            )?;
            let peer_shape = CanaryRouteShape::new(
                policy.rpdb().peer_return_table(),
                RouteProtocol::from_raw(policy.rpdb().route_protocol().get()),
                facility_route_scope(NetworkAddressFamily::Ipv6),
                policy.rpdb().route_metric(),
            )?;
            CanaryVethFamilyTopology::ipv6(128, 128, daemon_shape, peer_shape)
        })
        .transpose()?;
    CanaryPeerVethTopology::new(ipv4, ipv6).map_err(Into::into)
}

fn facility_host_route(
    destination: IpAddr,
    output_interface: InterfaceIndex,
    table: RouteTableId,
    policy: &ReviewedCanaryFacilityPolicy,
) -> FacilityHostRoute {
    FacilityHostRoute {
        destination,
        output_interface,
        table,
        protocol: RouteProtocol::from_raw(policy.rpdb().route_protocol().get()),
        scope: facility_route_scope(match destination {
            IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
            IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
        }),
        metric: policy.rpdb().route_metric(),
    }
}

const fn facility_route_scope(family: NetworkAddressFamily) -> RouteScope {
    RouteScope::from_raw(match family {
        NetworkAddressFamily::Ipv4 => FACILITY_ROUTE_SCOPE_LINK,
        NetworkAddressFamily::Ipv6 => FACILITY_ROUTE_SCOPE_UNIVERSE,
    })
}

fn facility_peer_rules(
    policy: &ReviewedCanaryFacilityPolicy,
    selected: SelectedFacilityCandidate,
) -> Vec<FacilityPeerRule> {
    let mut rules = Vec::with_capacity(
        if matches!(selected.families, CanaryAddressFamilies::Ipv4Only) {
            4
        } else {
            8
        },
    );
    let credentials = policy.credentials();
    let rpdb = policy.rpdb();
    for destination in std::iter::once(IpAddr::V4(selected.addresses.peer_ipv4())).chain(
        matches!(selected.families, CanaryAddressFamilies::Ipv4AndIpv6).then(|| {
            IpAddr::V6(
                selected
                    .addresses
                    .peer_ipv6()
                    .expect("dual-stack peer address"),
            )
        }),
    ) {
        for (transport_protocol, destination_port) in [
            (libc::IPPROTO_TCP as u8, selected.ports.tcp_echo().get()),
            (libc::IPPROTO_UDP as u8, selected.ports.udp_echo().get()),
            (libc::IPPROTO_TCP as u8, selected.ports.dns().get()),
            (libc::IPPROTO_UDP as u8, selected.ports.dns().get()),
        ] {
            rules.push(FacilityPeerRule {
                destination,
                engine_uid: credentials.engine_uid(),
                transport_protocol,
                destination_port,
                priority: rpdb.peer_rule_priority(),
                table: RuleTableId::from_raw(rpdb.peer_table().get()),
                protocol: RuleProtocol::from_raw(rpdb.rule_protocol().get()),
                proxy_mark_mask: rpdb.proxy_mark_mask(),
            });
        }
    }
    rules
}

fn unique_interface_index(
    inventory: &NetworkInventory,
    name: &[u8],
) -> Result<InterfaceIndex, NativeCanaryFacilityError> {
    let mut matches = inventory
        .links()
        .iter()
        .filter(|link| link.name().as_bytes() == name);
    let link = matches.next().ok_or(NativeCanaryFacilityError::Policy(
        "created canary veth is absent from complete readback",
    ))?;
    if matches.next().is_some() {
        return Err(NativeCanaryFacilityError::Policy(
            "created canary veth name is ambiguous in complete readback",
        ));
    }
    Ok(link.interface_index())
}

fn create_peer_network_namespace() -> Result<File, NativeCanaryFacilityError> {
    // Holder-domain invariant for the qualification-only anonymous-namespace audit: this
    // facility uses ordinary Rust threads and never unshares CLONE_FILES or CLONE_NEWNS. Worker
    // threads may change only their calling thread's CLONE_NEWNET, and `File::try_clone` keeps
    // every retained nsfs descriptor in the daemon's one process file table. The independent
    // audit therefore scans every task's network-namespace link plus the process FD/mount tables.
    std::thread::Builder::new()
        .name("flux-canary-netns-create".to_owned())
        .spawn(|| {
            // SAFETY: this fresh worker has not opened namespace-scoped resources and changes only
            // its calling thread's network namespace before exporting one retained nsfs handle.
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                return Err(NativeCanaryFacilityError::system(
                    "create peer network namespace",
                    io::Error::last_os_error(),
                ));
            }
            // SAFETY: gettid takes no pointer arguments and observes only the calling worker's
            // stable thread ID while that worker remains alive to open its namespace descriptor.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            let path = format!("/proc/self/task/{tid}/ns/net");
            File::open(path).map_err(|source| {
                NativeCanaryFacilityError::system("retain peer network namespace", source)
            })
        })
        .map_err(|source| NativeCanaryFacilityError::system("spawn namespace creator", source))?
        .join()
        .map_err(|_| NativeCanaryFacilityError::WorkerPanicked("create peer network namespace"))?
}

fn with_network_namespace<T: Send + 'static>(
    namespace: &File,
    operation: &'static str,
    action: impl FnOnce() -> Result<T, NativeCanaryFacilityError> + Send + 'static,
) -> Result<T, NativeCanaryFacilityError> {
    let namespace = namespace.try_clone().map_err(|source| {
        NativeCanaryFacilityError::system("duplicate network namespace for worker", source)
    })?;
    std::thread::Builder::new()
        .name(format!("flux-canary-{operation}"))
        .spawn(move || {
            // SAFETY: the retained descriptor was validated as the exact target nsfs network
            // namespace, and this fresh worker enters it before opening namespace-scoped handles.
            if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return Err(NativeCanaryFacilityError::system(
                    "enter peer network namespace",
                    io::Error::last_os_error(),
                ));
            }
            action()
        })
        .map_err(|source| NativeCanaryFacilityError::system("spawn namespace worker", source))?
        .join()
        .map_err(|_| NativeCanaryFacilityError::WorkerPanicked(operation))?
}

fn collect_inventory_in_namespace(
    namespace: &File,
) -> Result<Arc<NetworkInventory>, NativeCanaryFacilityError> {
    with_network_namespace(namespace, "inventory", || {
        collect_network_inventory_once(FACILITY_INVENTORY_TIMEOUT).map_err(|error| {
            NativeCanaryFacilityError::platform("collect peer network inventory", error)
        })
    })
}

fn configure_peer_namespace(
    namespace: &File,
    peer_veth_index: InterfaceIndex,
    selected: SelectedFacilityCandidate,
    routes: Vec<FacilityHostRoute>,
) -> Result<(), NativeCanaryFacilityError> {
    with_network_namespace(namespace, "configure-peer", move || {
        set_link_up(peer_veth_index)?;
        add_interface_address(peer_veth_index, IpAddr::V4(selected.addresses.peer_ipv4()))?;
        if let Some(address) = selected
            .addresses
            .peer_ipv6()
            .filter(|_| matches!(selected.families, CanaryAddressFamilies::Ipv4AndIpv6))
        {
            add_interface_address(peer_veth_index, IpAddr::V6(address))?;
        }
        for route in routes {
            mutate_route(route, true)?;
        }
        Ok(())
    })
}

fn listener_ports_are_clear_in_namespace(
    namespace: &File,
    ports: ReviewedCanaryResponderPortCandidate,
    families: CanaryAddressFamilies,
) -> Result<bool, NativeCanaryFacilityError> {
    let ports = CanaryResponderPorts::new(ports.tcp_echo(), ports.udp_echo(), ports.dns())?;
    listener_ports_are_clear_in_namespace_values(namespace, ports, families)
}

fn listener_ports_are_clear_in_namespace_values(
    namespace: &File,
    ports: CanaryResponderPorts,
    families: CanaryAddressFamilies,
) -> Result<bool, NativeCanaryFacilityError> {
    with_network_namespace(namespace, "listener-audit", move || {
        listener_ports_are_clear_values(ports, families)
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_created_facility_topology(
    policy: &ReviewedCanaryFacilityPolicy,
    selected: SelectedFacilityCandidate,
    daemon_veth_index: InterfaceIndex,
    peer_veth_index: InterfaceIndex,
    daemon_routes: &[FacilityHostRoute],
    peer_routes: &[FacilityHostRoute],
    daemon_inventory: &NetworkInventory,
    peer_inventory: &NetworkInventory,
) -> Result<(), NativeCanaryFacilityError> {
    validate_veth_readback(
        daemon_inventory,
        policy.daemon_veth_name().as_bytes(),
        daemon_veth_index,
        peer_veth_index,
    )?;
    validate_veth_readback(
        peer_inventory,
        policy.peer_veth_name().as_bytes(),
        peer_veth_index,
        daemon_veth_index,
    )?;
    validate_address_readback(
        daemon_inventory,
        peer_inventory,
        daemon_veth_index,
        IpAddr::V4(selected.addresses.daemon_ipv4()),
        selected
            .addresses
            .daemon_ipv6()
            .filter(|_| matches!(selected.families, CanaryAddressFamilies::Ipv4AndIpv6))
            .map(IpAddr::V6),
    )?;
    validate_address_readback(
        peer_inventory,
        daemon_inventory,
        peer_veth_index,
        IpAddr::V4(selected.addresses.peer_ipv4()),
        selected
            .addresses
            .peer_ipv6()
            .filter(|_| matches!(selected.families, CanaryAddressFamilies::Ipv4AndIpv6))
            .map(IpAddr::V6),
    )?;
    validate_route_readback("daemon", daemon_inventory, daemon_routes)?;
    validate_route_readback("peer", peer_inventory, peer_routes)?;
    Ok(())
}

fn validate_veth_readback(
    inventory: &NetworkInventory,
    name: &[u8],
    index: InterfaceIndex,
    peer_index: InterfaceIndex,
) -> Result<(), NativeCanaryFacilityError> {
    let matches = inventory
        .links()
        .iter()
        .filter(|link| link.interface_index() == index || link.name().as_bytes() == name)
        .collect::<Vec<_>>();
    if matches.len() != 1
        || matches[0].interface_index() != index
        || matches[0].name().as_bytes() != name
        || matches[0].kind().map(|kind| kind.as_bytes()) != Some(b"veth".as_slice())
        || matches[0].link_reference()
            != Some(flux_core::InterfaceLinkReference::Interface(peer_index))
    {
        return Err(NativeCanaryFacilityError::Policy(
            "created canary veth failed exact reciprocal readback",
        ));
    }
    Ok(())
}

fn validate_address_readback(
    inventory: &NetworkInventory,
    other_inventory: &NetworkInventory,
    interface: InterfaceIndex,
    ipv4: IpAddr,
    ipv6: Option<IpAddr>,
) -> Result<(), NativeCanaryFacilityError> {
    let expected = [Some(ipv4), ipv6];
    let mut link_local_count = 0_usize;
    for observed in inventory
        .addresses()
        .iter()
        .filter(|observed| observed.interface_index() == interface)
    {
        if expected.contains(&Some(observed.address())) {
            continue;
        }
        if matches!(observed.address(), IpAddr::V6(value) if value.segments()[0] & 0xffc0 == 0xfe80)
            && observed.prefix_length() == 64
        {
            link_local_count = link_local_count.saturating_add(1);
            continue;
        }
        return Err(NativeCanaryFacilityError::Policy(
            "created canary veth carries an unexpected non-link-local address",
        ));
    }
    if link_local_count > 1 {
        return Err(NativeCanaryFacilityError::Policy(
            "created canary veth carries duplicate link-local addresses",
        ));
    }

    for address in std::iter::once(ipv4).chain(ipv6) {
        let expected_prefix = host_prefix_length(match address {
            IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
            IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
        });
        let matches = inventory
            .addresses()
            .iter()
            .filter(|observed| observed.address() == address)
            .collect::<Vec<_>>();
        if matches.len() != 1
            || matches[0].interface_index() != interface
            || matches[0].prefix_length() != expected_prefix
            || matches[0].flags().intersects(
                flux_core::InterfaceAddressFlags::TENTATIVE
                    | flux_core::InterfaceAddressFlags::DAD_FAILED
                    | flux_core::InterfaceAddressFlags::DEPRECATED,
            )
            || other_inventory
                .addresses()
                .iter()
                .any(|observed| observed.address() == address)
        {
            return Err(NativeCanaryFacilityError::Policy(
                "created canary address failed exact readback",
            ));
        }
    }
    Ok(())
}

fn validate_route_readback(
    domain: &'static str,
    inventory: &NetworkInventory,
    routes: &[FacilityHostRoute],
) -> Result<(), NativeCanaryFacilityError> {
    let expected = routes
        .iter()
        .copied()
        .map(expected_route_record)
        .collect::<Result<Vec<_>, _>>()?;
    let actual = inventory
        .routes()
        .iter()
        .filter(|route| {
            routes.iter().any(|expected| {
                route.properties().table() == expected.table
                    && route.properties().protocol() == expected.protocol
            })
        })
        .collect::<Vec<_>>();
    if actual.len() != expected.len()
        || expected.iter().any(|candidate| {
            actual
                .iter()
                .filter(|actual| ***actual == *candidate)
                .count()
                != 1
        })
        || actual
            .iter()
            .any(|actual| !expected.iter().any(|candidate| **actual == *candidate))
    {
        let mismatches = route_readback_mismatch_fields(inventory, &expected, &actual);
        return Err(NativeCanaryFacilityError::Platform(
            format!(
                "created {domain} canary route cohort failed exact readback: mismatch={}",
                mismatches.join(",")
            )
            .into_boxed_str(),
        ));
    }
    Ok(())
}

fn route_readback_mismatch_fields(
    inventory: &NetworkInventory,
    expected: &[flux_core::NetworkRouteRecord],
    actual: &[&flux_core::NetworkRouteRecord],
) -> Vec<&'static str> {
    fn push_unique(fields: &mut Vec<&'static str>, field: &'static str) {
        if !fields.contains(&field) {
            fields.push(field);
        }
    }

    let mut fields = Vec::new();
    if actual.len() != expected.len() {
        push_unique(&mut fields, "cohort_cardinality");
    }
    for expected in expected {
        let candidates = inventory
            .routes()
            .iter()
            .filter(|candidate| candidate.destination() == expected.destination())
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            push_unique(&mut fields, "destination_cardinality");
            continue;
        }
        let actual = candidates[0];
        if actual.source() != expected.source() {
            push_unique(&mut fields, "source");
        }
        let actual_properties = actual.properties();
        let expected_properties = expected.properties();
        if actual_properties.tos() != expected_properties.tos() {
            push_unique(&mut fields, "tos");
        }
        if actual_properties.table() != expected_properties.table() {
            push_unique(&mut fields, "table");
        }
        if actual_properties.protocol() != expected_properties.protocol() {
            push_unique(&mut fields, "protocol");
        }
        if actual_properties.scope() != expected_properties.scope() {
            push_unique(&mut fields, "scope");
        }
        if actual_properties.route_type() != expected_properties.route_type() {
            push_unique(&mut fields, "type");
        }
        if actual_properties.flags() != expected_properties.flags() {
            push_unique(&mut fields, "flags");
        }
        if actual.priority() != expected.priority() {
            push_unique(&mut fields, "priority");
        }
        if actual.preferred_source() != expected.preferred_source() {
            push_unique(&mut fields, "preferred_source");
        }
        if actual.preference() != expected.preference() {
            push_unique(&mut fields, "preference");
        }
        if actual.nexthop_id() != expected.nexthop_id() {
            push_unique(&mut fields, "nexthop_id");
        }
        if actual.path() != expected.path() {
            push_unique(&mut fields, "path");
        }
    }
    if fields.is_empty() {
        fields.push("record_identity");
    }
    fields
}

fn validate_rule_readback(
    inventory: &NetworkInventory,
    rules: &[FacilityPeerRule],
) -> Result<(), NativeCanaryFacilityError> {
    let expected = rules
        .iter()
        .copied()
        .map(expected_rule_record)
        .collect::<Result<Vec<_>, _>>()?;
    let actual = inventory
        .rules()
        .iter()
        .filter(|rule| {
            rules.iter().any(|expected| {
                rule.priority() == expected.priority || rule.properties().table() == expected.table
            })
        })
        .collect::<Vec<_>>();
    if actual.len() != expected.len()
        || expected.iter().any(|candidate| {
            actual
                .iter()
                .filter(|actual| ***actual == *candidate)
                .count()
                != 1
        })
        || actual
            .iter()
            .any(|actual| !expected.iter().any(|candidate| **actual == *candidate))
    {
        let mismatches = rule_readback_mismatch_fields(&expected, &actual);
        return Err(NativeCanaryFacilityError::Platform(
            format!(
                "created canary RPDB cohort failed exact readback: mismatch={}",
                mismatches.join(",")
            )
            .into_boxed_str(),
        ));
    }
    Ok(())
}

fn rule_readback_mismatch_fields(
    expected: &[flux_core::NetworkRuleRecord],
    actual: &[&flux_core::NetworkRuleRecord],
) -> Vec<&'static str> {
    fn push_unique(fields: &mut Vec<&'static str>, field: &'static str) {
        if !fields.contains(&field) {
            fields.push(field);
        }
    }

    fn same_multiset<T: Ord>(
        expected: impl IntoIterator<Item = T>,
        actual: impl IntoIterator<Item = T>,
    ) -> bool {
        let mut expected = expected.into_iter().collect::<Vec<_>>();
        let mut actual = actual.into_iter().collect::<Vec<_>>();
        expected.sort_unstable();
        actual.sort_unstable();
        expected == actual
    }

    macro_rules! compare_multiset {
        ($fields:ident, $field:literal, $accessor:ident) => {
            if !same_multiset(
                expected.iter().map(|rule| rule.$accessor()),
                actual.iter().map(|rule| rule.$accessor()),
            ) {
                push_unique(&mut $fields, $field);
            }
        };
    }

    let mut fields = Vec::new();
    if actual.len() != expected.len() {
        push_unique(&mut fields, "cohort_cardinality");
    }
    compare_multiset!(fields, "destination", destination);
    compare_multiset!(fields, "source", source);
    compare_multiset!(fields, "priority", priority);
    compare_multiset!(fields, "goto_target", goto_target);
    compare_multiset!(fields, "fwmark", fwmark);
    compare_multiset!(fields, "tunnel_id", tunnel_id);
    compare_multiset!(fields, "suppress_interface_group", suppress_interface_group);
    compare_multiset!(fields, "suppress_prefix_length", suppress_prefix_length);
    compare_multiset!(fields, "l3mdev", l3mdev);
    compare_multiset!(fields, "uid_range", uid_range);
    compare_multiset!(fields, "ip_protocol", ip_protocol);
    compare_multiset!(fields, "source_port_range", source_port_range);
    compare_multiset!(fields, "destination_port_range", destination_port_range);
    compare_multiset!(fields, "flow", flow);
    if !same_multiset(
        expected.iter().map(|rule| rule.input_interface().cloned()),
        actual.iter().map(|rule| rule.input_interface().cloned()),
    ) {
        push_unique(&mut fields, "input_interface");
    }
    if !same_multiset(
        expected.iter().map(|rule| rule.output_interface().cloned()),
        actual.iter().map(|rule| rule.output_interface().cloned()),
    ) {
        push_unique(&mut fields, "output_interface");
    }
    if !same_multiset(
        expected.iter().map(|rule| rule.properties().tos()),
        actual.iter().map(|rule| rule.properties().tos()),
    ) {
        push_unique(&mut fields, "tos");
    }
    if !same_multiset(
        expected.iter().map(|rule| rule.properties().table()),
        actual.iter().map(|rule| rule.properties().table()),
    ) {
        push_unique(&mut fields, "table");
    }
    if !same_multiset(
        expected.iter().map(|rule| rule.properties().action()),
        actual.iter().map(|rule| rule.properties().action()),
    ) {
        push_unique(&mut fields, "action");
    }
    if !same_multiset(
        expected.iter().map(|rule| rule.properties().protocol()),
        actual.iter().map(|rule| rule.properties().protocol()),
    ) {
        push_unique(&mut fields, "protocol");
    }
    if !same_multiset(
        expected.iter().map(|rule| rule.properties().flags()),
        actual.iter().map(|rule| rule.properties().flags()),
    ) {
        push_unique(&mut fields, "flags");
    }
    if !same_multiset(
        expected
            .iter()
            .map(flux_core::NetworkRuleRecord::has_complete_attribute_coverage),
        actual
            .iter()
            .map(|rule| rule.has_complete_attribute_coverage()),
    ) {
        push_unique(&mut fields, "attribute_coverage");
    }
    if fields.is_empty() {
        fields.push("record_identity");
    }
    fields
}

fn expected_route_record(
    route: FacilityHostRoute,
) -> Result<flux_core::NetworkRouteRecord, NativeCanaryFacilityError> {
    let family = match route.destination {
        IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
        IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
    };
    let record = flux_core::NetworkRouteRecord::new(
        RoutePrefix::new(route.destination, host_prefix_length(family))
            .map_err(|_| NativeCanaryFacilityError::Policy("invalid canary route prefix"))?,
        RoutePrefix::unspecified(family),
        RouteProperties::new(
            0,
            route.table,
            route.protocol,
            route.scope,
            RouteType::from_raw(FACILITY_ROUTE_TYPE_UNICAST),
            RouteFlags::from_raw(0),
        ),
        route.metric.get(),
        RoutePath::Single {
            output_interface: Some(route.output_interface),
            gateway: None,
        },
    )
    .map_err(|_| NativeCanaryFacilityError::Policy("invalid canary route record"))?;
    match family {
        NetworkAddressFamily::Ipv4 => Ok(record),
        NetworkAddressFamily::Ipv6 => record
            .with_preference(RoutePreference::from_raw(0))
            .map_err(|_| NativeCanaryFacilityError::Policy("invalid IPv6 canary route record")),
    }
}

fn expected_rule_record(
    rule: FacilityPeerRule,
) -> Result<flux_core::NetworkRuleRecord, NativeCanaryFacilityError> {
    let family = match rule.destination {
        IpAddr::V4(_) => NetworkAddressFamily::Ipv4,
        IpAddr::V6(_) => NetworkAddressFamily::Ipv6,
    };
    let record = flux_core::NetworkRuleRecord::new(
        RulePrefix::new(rule.destination, host_prefix_length(family))
            .map_err(|_| NativeCanaryFacilityError::Policy("invalid canary rule prefix"))?,
        RulePrefix::unspecified(family),
        RuleProperties::new(
            0,
            rule.table,
            RuleAction::TO_TABLE,
            rule.protocol,
            RuleFlags::from_raw(0),
        ),
        rule.priority,
        None,
    )
    .map_err(|_| NativeCanaryFacilityError::Policy("invalid canary rule record"))?
    .with_fwmark(RuleFwMark::new(0, rule.proxy_mark_mask.get()).ok_or(
        NativeCanaryFacilityError::Policy("invalid canary rule mark mask"),
    )?)
    .with_uid_range(
        RuleUidRange::new(rule.engine_uid.get(), rule.engine_uid.get())
            .map_err(|_| NativeCanaryFacilityError::Policy("invalid canary rule UID"))?,
    )
    .with_ip_protocol(RuleIpProtocol::new(rule.transport_protocol).ok_or(
        NativeCanaryFacilityError::Policy("invalid canary rule transport protocol"),
    )?)
    .with_destination_port_range(
        RulePortRange::new(rule.destination_port, rule.destination_port)
            .map_err(|_| NativeCanaryFacilityError::Policy("invalid canary rule port"))?,
    );
    if !record.has_complete_attribute_coverage() {
        return Err(NativeCanaryFacilityError::Policy(
            "canary rule record has incomplete attribute coverage",
        ));
    }
    Ok(record)
}

fn live_facility_digest(
    policy: &ReviewedCanaryFacilityPolicy,
    selected: SelectedFacilityCandidate,
    facility: CanaryFacilityIdentity,
    peer_namespace: NetworkNamespaceIdentity,
    pre_inventory: &NetworkInventory,
    daemon_inventory: &NetworkInventory,
    peer_inventory: &NetworkInventory,
) -> Result<CanaryFacilityAuditDigest, NativeCanaryFacilityError> {
    let mut digest = Sha256::new();
    digest.update(FACILITY_AUDIT_DIGEST_DOMAIN);
    digest.update(policy.artifact_digest().as_bytes());
    digest.update(pre_inventory.epoch().get().to_be_bytes());
    digest.update(pre_inventory.snapshot_id().get().to_be_bytes());
    digest.update(daemon_inventory.epoch().get().to_be_bytes());
    digest.update(daemon_inventory.snapshot_id().get().to_be_bytes());
    digest.update(peer_inventory.epoch().get().to_be_bytes());
    digest.update(peer_inventory.snapshot_id().get().to_be_bytes());
    digest.update(peer_namespace.device().to_be_bytes());
    digest.update(peer_namespace.inode().to_be_bytes());
    digest.update(facility.daemon_veth().interface_index().get().to_be_bytes());
    digest.update(facility.peer_veth().interface_index().get().to_be_bytes());
    digest.update(selected.addresses.daemon_ipv4().octets());
    digest.update(selected.addresses.peer_ipv4().octets());
    digest.update(
        selected
            .addresses
            .daemon_ipv6()
            .map_or([0; 16], |value| value.octets()),
    );
    digest.update(
        selected
            .addresses
            .peer_ipv6()
            .map_or([0; 16], |value| value.octets()),
    );
    for port in [
        selected.ports.tcp_echo(),
        selected.ports.udp_echo(),
        selected.ports.dns(),
    ] {
        digest.update(port.get().to_be_bytes());
    }
    CanaryFacilityAuditDigest::new(digest.finalize().into()).map_err(Into::into)
}

const NLMSG_HEADER_LENGTH: usize = 16;
const IFINFO_MESSAGE_LENGTH: usize = 16;
const IFADDR_MESSAGE_LENGTH: usize = 8;
const ROUTE_MESSAGE_LENGTH: usize = 12;
const NETLINK_ATTRIBUTE_HEADER_LENGTH: usize = 4;
const NETLINK_ACK_BUFFER_BYTES: usize = 8 * 1024;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const NLMSG_ERROR: u16 = 2;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLA_F_NESTED: u16 = 0x8000;

const IFLA_IFNAME: u16 = 3;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
const IFA_F_NODAD: u32 = 0x02;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;
const FRA_DST: u16 = 1;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_UID_RANGE: u16 = 20;
const FRA_PROTOCOL: u16 = 21;
const FRA_IP_PROTO: u16 = 22;
const FRA_DPORT_RANGE: u16 = 24;
const FR_ACT_TO_TBL: u8 = 1;
const RT_TABLE_COMPAT: u8 = 252;

fn mutation_flags(add: bool) -> u16 {
    if add {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    } else {
        NLM_F_REQUEST | NLM_F_ACK
    }
}

fn create_veth_pair(
    daemon_name: &[u8],
    peer_name: &[u8],
    peer_namespace_fd: RawFd,
) -> Result<(), NativeCanaryFacilityError> {
    execute_netlink_request(&encode_veth_pair_request(
        daemon_name,
        peer_name,
        peer_namespace_fd,
    )?)
}

fn encode_veth_pair_request(
    daemon_name: &[u8],
    peer_name: &[u8],
    peer_namespace_fd: RawFd,
) -> Result<Vec<u8>, NativeCanaryFacilityError> {
    let mut peer = vec![0_u8; IFINFO_MESSAGE_LENGTH];
    append_string_attribute(&mut peer, IFLA_IFNAME, peer_name)?;
    append_attribute(&mut peer, IFLA_NET_NS_FD, &peer_namespace_fd.to_ne_bytes())?;
    let mut info_data = Vec::new();
    append_attribute(&mut info_data, VETH_INFO_PEER | NLA_F_NESTED, &peer)?;
    let mut link_info = Vec::new();
    append_string_attribute(&mut link_info, IFLA_INFO_KIND, b"veth")?;
    append_attribute(&mut link_info, IFLA_INFO_DATA | NLA_F_NESTED, &info_data)?;
    let mut body = vec![0_u8; IFINFO_MESSAGE_LENGTH];
    append_string_attribute(&mut body, IFLA_IFNAME, daemon_name)?;
    append_attribute(&mut body, IFLA_LINKINFO | NLA_F_NESTED, &link_info)?;
    finish_request(RTM_NEWLINK, mutation_flags(true), &body)
}

fn set_link_up(index: InterfaceIndex) -> Result<(), NativeCanaryFacilityError> {
    let mut body = vec![0_u8; IFINFO_MESSAGE_LENGTH];
    body[4..8].copy_from_slice(&(index.get() as i32).to_ne_bytes());
    body[8..12].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    body[12..16].copy_from_slice(&(libc::IFF_UP as u32).to_ne_bytes());
    execute_netlink_request(&finish_request(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        &body,
    )?)
}

fn delete_link(index: InterfaceIndex) -> Result<(), NativeCanaryFacilityError> {
    let mut body = vec![0_u8; IFINFO_MESSAGE_LENGTH];
    body[4..8].copy_from_slice(&(index.get() as i32).to_ne_bytes());
    execute_netlink_request(&finish_request(
        RTM_DELLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        &body,
    )?)
}

fn add_interface_address(
    index: InterfaceIndex,
    address: IpAddr,
) -> Result<(), NativeCanaryFacilityError> {
    let (family, prefix, bytes, flags) = match address {
        IpAddr::V4(address) => (libc::AF_INET as u8, 32, address.octets().to_vec(), 0),
        IpAddr::V6(address) => (
            libc::AF_INET6 as u8,
            128,
            address.octets().to_vec(),
            IFA_F_NODAD,
        ),
    };
    let mut body = vec![0_u8; IFADDR_MESSAGE_LENGTH];
    body[0] = family;
    body[1] = prefix;
    body[2] = u8::try_from(flags).expect("NODAD fits the legacy flag byte");
    body[3] = 0;
    body[4..8].copy_from_slice(&index.get().to_ne_bytes());
    append_attribute(&mut body, IFA_ADDRESS, &bytes)?;
    append_attribute(&mut body, IFA_LOCAL, &bytes)?;
    append_attribute(&mut body, IFA_FLAGS, &flags.to_ne_bytes())?;
    execute_netlink_request(&finish_request(RTM_NEWADDR, mutation_flags(true), &body)?)
}

fn mutate_route(route: FacilityHostRoute, add: bool) -> Result<(), NativeCanaryFacilityError> {
    let (family, prefix, destination) = match route.destination {
        IpAddr::V4(address) => (libc::AF_INET as u8, 32, address.octets().to_vec()),
        IpAddr::V6(address) => (libc::AF_INET6 as u8, 128, address.octets().to_vec()),
    };
    let mut body = vec![0_u8; ROUTE_MESSAGE_LENGTH];
    body[0] = family;
    body[1] = prefix;
    body[4] = table_header_byte(route.table.get());
    body[5] = route.protocol.raw();
    body[6] = route.scope.raw();
    body[7] = FACILITY_ROUTE_TYPE_UNICAST;
    append_attribute(&mut body, RTA_DST, &destination)?;
    append_attribute(&mut body, RTA_TABLE, &route.table.get().to_ne_bytes())?;
    append_attribute(
        &mut body,
        RTA_OIF,
        &route.output_interface.get().to_ne_bytes(),
    )?;
    append_attribute(&mut body, RTA_PRIORITY, &route.metric.get().to_ne_bytes())?;
    execute_netlink_request(&finish_request(
        if add { RTM_NEWROUTE } else { RTM_DELROUTE },
        mutation_flags(add),
        &body,
    )?)
}

fn mutate_peer_rule(rule: FacilityPeerRule, add: bool) -> Result<(), NativeCanaryFacilityError> {
    execute_netlink_request(&encode_peer_rule_request(rule, add)?)
}

fn encode_peer_rule_request(
    rule: FacilityPeerRule,
    add: bool,
) -> Result<Vec<u8>, NativeCanaryFacilityError> {
    let (family, prefix, destination) = match rule.destination {
        IpAddr::V4(address) => (libc::AF_INET as u8, 32, address.octets().to_vec()),
        IpAddr::V6(address) => (libc::AF_INET6 as u8, 128, address.octets().to_vec()),
    };
    let mut body = vec![0_u8; ROUTE_MESSAGE_LENGTH];
    body[0] = family;
    body[1] = prefix;
    body[4] = table_header_byte(rule.table.get());
    body[7] = FR_ACT_TO_TBL;
    append_attribute(&mut body, FRA_DST, &destination)?;
    append_attribute(&mut body, FRA_TABLE, &rule.table.get().to_ne_bytes())?;
    append_attribute(&mut body, FRA_PRIORITY, &rule.priority.get().to_ne_bytes())?;
    append_attribute(&mut body, FRA_FWMARK, &0_u32.to_ne_bytes())?;
    append_attribute(
        &mut body,
        FRA_FWMASK,
        &rule.proxy_mark_mask.get().to_ne_bytes(),
    )?;
    let mut uid_range = Vec::with_capacity(8);
    uid_range.extend_from_slice(&rule.engine_uid.get().to_ne_bytes());
    uid_range.extend_from_slice(&rule.engine_uid.get().to_ne_bytes());
    append_attribute(&mut body, FRA_UID_RANGE, &uid_range)?;
    append_attribute(&mut body, FRA_PROTOCOL, &[rule.protocol.raw()])?;
    append_attribute(&mut body, FRA_IP_PROTO, &[rule.transport_protocol])?;
    let mut port_range = Vec::with_capacity(4);
    port_range.extend_from_slice(&rule.destination_port.to_ne_bytes());
    port_range.extend_from_slice(&rule.destination_port.to_ne_bytes());
    append_attribute(&mut body, FRA_DPORT_RANGE, &port_range)?;
    finish_request(
        if add { RTM_NEWRULE } else { RTM_DELRULE },
        mutation_flags(add),
        &body,
    )
}

const fn table_header_byte(table: u32) -> u8 {
    if table <= u8::MAX as u32 {
        table as u8
    } else {
        RT_TABLE_COMPAT
    }
}

fn append_string_attribute(
    target: &mut Vec<u8>,
    attribute_type: u16,
    value: &[u8],
) -> Result<(), NativeCanaryFacilityError> {
    let mut terminated = Vec::with_capacity(value.len().saturating_add(1));
    terminated.extend_from_slice(value);
    terminated.push(0);
    append_attribute(target, attribute_type, &terminated)
}

fn append_attribute(
    target: &mut Vec<u8>,
    attribute_type: u16,
    value: &[u8],
) -> Result<(), NativeCanaryFacilityError> {
    let length = NETLINK_ATTRIBUTE_HEADER_LENGTH
        .checked_add(value.len())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(NativeCanaryFacilityError::Policy(
            "canary rtnetlink attribute exceeds the ABI limit",
        ))?;
    let aligned = align4(usize::from(length));
    let start = target.len();
    let end = start
        .checked_add(aligned)
        .ok_or(NativeCanaryFacilityError::Policy(
            "canary rtnetlink request length overflowed",
        ))?;
    target.resize(end, 0);
    target[start..start + 2].copy_from_slice(&length.to_ne_bytes());
    target[start + 2..start + 4].copy_from_slice(&attribute_type.to_ne_bytes());
    target[start + 4..start + 4 + value.len()].copy_from_slice(value);
    Ok(())
}

fn finish_request(
    message_type: u16,
    flags: u16,
    body: &[u8],
) -> Result<Vec<u8>, NativeCanaryFacilityError> {
    let length = NLMSG_HEADER_LENGTH
        .checked_add(body.len())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(NativeCanaryFacilityError::Policy(
            "canary rtnetlink request exceeds the ABI limit",
        ))?;
    let mut request = Vec::with_capacity(length as usize);
    request.extend_from_slice(&length.to_ne_bytes());
    request.extend_from_slice(&message_type.to_ne_bytes());
    request.extend_from_slice(&flags.to_ne_bytes());
    request.extend_from_slice(&1_u32.to_ne_bytes());
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.extend_from_slice(body);
    Ok(request)
}

const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn execute_netlink_request(request: &[u8]) -> Result<(), NativeCanaryFacilityError> {
    let descriptor = open_route_netlink()?;
    // SAFETY: all-zero is a valid sockaddr_nl base; the family field is initialized below and
    // zero selects the kernel destination port and no multicast groups.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: request remains readable for its exact length, kernel has the sockaddr_nl ABI, and
    // descriptor owns a live NETLINK_ROUTE socket for the duration of the call.
    let sent = unsafe {
        libc::sendto(
            descriptor.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&raw const kernel).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(NativeCanaryFacilityError::system(
            "send canary rtnetlink mutation",
            io::Error::last_os_error(),
        ));
    }
    if usize::try_from(sent).ok() != Some(request.len()) {
        return Err(NativeCanaryFacilityError::Policy(
            "canary rtnetlink mutation was short-written",
        ));
    }
    receive_netlink_ack(&descriptor)
}

fn open_route_netlink() -> Result<OwnedFd, NativeCanaryFacilityError> {
    // SAFETY: socket takes no pointer arguments and returns one new descriptor on success;
    // CLOEXEC is applied atomically.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(NativeCanaryFacilityError::system(
            "open canary rtnetlink mutation socket",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: the successful socket call returned one new descriptor, transferred exactly once.
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: all-zero is a valid sockaddr_nl base; the family field is initialized below and the
    // zero port and groups request a kernel-assigned unicast endpoint.
    let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: local has the sockaddr_nl ABI and remains readable for the exact declared size while
    // descriptor owns the NETLINK_ROUTE socket.
    if unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            (&raw const local).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(NativeCanaryFacilityError::system(
            "bind canary rtnetlink mutation socket",
            io::Error::last_os_error(),
        ));
    }
    Ok(descriptor)
}

fn receive_netlink_ack(descriptor: &OwnedFd) -> Result<(), NativeCanaryFacilityError> {
    let deadline = Instant::now()
        .checked_add(FACILITY_MUTATION_TIMEOUT)
        .ok_or(NativeCanaryFacilityError::Policy(
            "canary mutation deadline overflowed",
        ))?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(NativeCanaryFacilityError::Policy(
                "canary rtnetlink mutation acknowledgement timed out",
            ));
        }
        let mut pollfd = libc::pollfd {
            fd: descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: pollfd points to one initialized writable descriptor record for this bounded
        // poll call, and descriptor keeps the referenced FD alive.
        let polled = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
        if polled < 0 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(NativeCanaryFacilityError::system(
                "wait for canary rtnetlink acknowledgement",
                source,
            ));
        }
        if polled == 0 {
            continue;
        }
        if pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(NativeCanaryFacilityError::Policy(
                "canary rtnetlink acknowledgement socket reported terminal events",
            ));
        }
        let mut bytes = [0_u8; NETLINK_ACK_BUFFER_BYTES];
        // SAFETY: all-zero is a valid sockaddr_nl output buffer; recvfrom initializes the reported
        // sender fields before they are inspected.
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut sender_length = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: bytes and sender are writable for their declared lengths, sender_length is a
        // writable socklen_t, and descriptor owns a live NETLINK_ROUTE socket.
        let received = unsafe {
            libc::recvfrom(
                descriptor.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_TRUNC,
                (&raw mut sender).cast(),
                &raw mut sender_length,
            )
        };
        if received < 0 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(NativeCanaryFacilityError::system(
                "receive canary rtnetlink acknowledgement",
                source,
            ));
        }
        let received = usize::try_from(received).map_err(|_| {
            NativeCanaryFacilityError::Policy("negative rtnetlink length passed validation")
        })?;
        if received > bytes.len()
            || sender_length as usize != std::mem::size_of::<libc::sockaddr_nl>()
            || sender.nl_pid != 0
        {
            return Err(NativeCanaryFacilityError::Policy(
                "canary rtnetlink acknowledgement has invalid sender or length",
            ));
        }
        return decode_netlink_ack(&bytes[..received]);
    }
}

fn decode_netlink_ack(bytes: &[u8]) -> Result<(), NativeCanaryFacilityError> {
    if bytes.len() < NLMSG_HEADER_LENGTH + 4 {
        return Err(NativeCanaryFacilityError::Policy(
            "canary rtnetlink acknowledgement is truncated",
        ));
    }
    let length = u32::from_ne_bytes(bytes[0..4].try_into().expect("four-byte netlink length"));
    let length = usize::try_from(length).map_err(|_| {
        NativeCanaryFacilityError::Policy("canary rtnetlink length does not fit this target")
    })?;
    let message_type = u16::from_ne_bytes(bytes[4..6].try_into().expect("two-byte netlink type"));
    let sequence = u32::from_ne_bytes(bytes[8..12].try_into().expect("four-byte sequence"));
    if length < NLMSG_HEADER_LENGTH + 4
        || length > bytes.len()
        || message_type != NLMSG_ERROR
        || sequence != 1
    {
        return Err(NativeCanaryFacilityError::Policy(
            "canary rtnetlink mutation returned a noncanonical acknowledgement",
        ));
    }
    let status = i32::from_ne_bytes(
        bytes[NLMSG_HEADER_LENGTH..NLMSG_HEADER_LENGTH + 4]
            .try_into()
            .expect("four-byte netlink status"),
    );
    if status == 0 {
        Ok(())
    } else {
        Err(NativeCanaryFacilityError::system(
            "apply canary rtnetlink mutation",
            io::Error::from_raw_os_error(status.saturating_neg()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::net::TcpListener;
    use std::os::unix::net::UnixStream;

    use super::*;
    use crate::functional_canary::CanaryUserNamespaceBinding;

    const TEST_ROLE_UIDS: [u32; 2] = [20_001, 20_002];
    const TEST_ROLE_GIDS: [u32; 2] = [30_001, 30_002];

    fn test_namespace(device: u64, inode: u64) -> CanaryFileIdentity {
        CanaryFileIdentity::new(
            device,
            NonZeroU64::new(inode).expect("test namespace inode is nonzero"),
        )
    }

    #[test]
    fn qualification_peer_netns_report_is_one_canonical_big_endian_frame() {
        let identity = NetworkNamespaceIdentity::new(0x0102_0304_0506_0708, 0x1112_1314_1516_1718)
            .expect("test peer namespace identity");

        assert_eq!(
            encode_qualification_peer_netns_report(identity),
            *b"FLXQ11NS\x00\x01\x00\x10\x01\x02\x03\x04\x05\x06\x07\x08\x11\x12\x13\x14\x15\x16\x17\x18"
        );
    }

    #[test]
    fn qualification_peer_netns_report_writer_closes_the_transferred_descriptor() {
        let identity = NetworkNamespaceIdentity::new(17, 19).expect("test namespace identity");
        let (mut reader, writer) = UnixStream::pair().expect("report pipe");

        write_qualification_peer_netns_report(writer.into(), identity)
            .expect("write qualification report");

        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .expect("read report through EOF");
        assert_eq!(bytes, encode_qualification_peer_netns_report(identity));
    }

    #[test]
    fn qualification_peer_netns_report_writer_keeps_errors_identity_free() {
        let identity = NetworkNamespaceIdentity::new(0x0102_0304, 0x0506_0708)
            .expect("test namespace identity");
        let (reader, writer) = UnixStream::pair().expect("report pipe");
        drop(reader);

        let error = write_qualification_peer_netns_report(writer.into(), identity)
            .expect_err("closed report reader must fail");
        let rendered = error.to_string();
        assert!(!rendered.contains("16909060"));
        assert!(!rendered.contains("84281096"));
    }

    #[test]
    fn coherent_absent_user_namespace_facility_binds_unsupported_domain() {
        let mount = test_namespace(41, 42);
        let domain =
            bind_current_credential_domain(None, mount, None, None, TEST_ROLE_UIDS, TEST_ROLE_GIDS)
                .expect("coherently absent user namespace facilities are supported evidence");

        assert_eq!(
            domain.user_namespace(),
            CanaryUserNamespaceBinding::Unsupported
        );
        assert_eq!(domain.mount_namespace(), mount);
    }

    #[test]
    fn coherent_user_namespace_facility_binds_descriptor_and_exact_maps() {
        let user = test_namespace(51, 52);
        let mount = test_namespace(61, 62);
        let uid_map = b"0 0 1\n20001 50001 2\n";
        let gid_map = b"0 0 1\n30001 60001 2\n";
        let domain = bind_current_credential_domain(
            Some(user),
            mount,
            Some(uid_map),
            Some(gid_map),
            TEST_ROLE_UIDS,
            TEST_ROLE_GIDS,
        )
        .expect("coherent mapped user namespace facility");
        let expected_uid = flux_platform::internal::digest_current_process_id_map(
            uid_map,
            ProcessCredentialMapKind::Uid,
        )
        .expect("digest test UID map");
        let expected_gid = flux_platform::internal::digest_current_process_id_map(
            gid_map,
            ProcessCredentialMapKind::Gid,
        )
        .expect("digest test GID map");

        assert_eq!(domain.mount_namespace(), mount);
        assert_eq!(
            domain.user_namespace(),
            CanaryUserNamespaceBinding::Observed {
                namespace: user,
                uid_map_digest: CanaryCredentialMapDigest::new(*expected_uid.as_bytes())
                    .expect("test UID map digest is nonzero"),
                gid_map_digest: CanaryCredentialMapDigest::new(*expected_gid.as_bytes())
                    .expect("test GID map digest is nonzero"),
            }
        );
    }

    #[test]
    fn mixed_user_namespace_facility_presence_is_rejected() {
        let user = test_namespace(51, 52);
        let mount = test_namespace(61, 62);
        let uid_map = b"0 0 1\n20001 50001 2\n".as_slice();
        let gid_map = b"0 0 1\n30001 60001 2\n".as_slice();

        for (user, uid_map, gid_map) in [
            (Some(user), None, None),
            (None, Some(uid_map), None),
            (None, None, Some(gid_map)),
            (Some(user), Some(uid_map), None),
            (Some(user), None, Some(gid_map)),
            (None, Some(uid_map), Some(gid_map)),
        ] {
            assert!(matches!(
                bind_current_credential_domain(
                    user,
                    mount,
                    uid_map,
                    gid_map,
                    TEST_ROLE_UIDS,
                    TEST_ROLE_GIDS,
                ),
                Err(NativeCanaryFacilityError::Policy(
                    "daemon user namespace and credential maps have incoherent presence"
                ))
            ));
        }
    }

    #[test]
    fn mapped_user_namespace_requires_every_reviewed_role_id() {
        let user = test_namespace(51, 52);
        let mount = test_namespace(61, 62);
        let uid_map = b"0 0 1\n20001 50001 2\n";
        let gid_map = b"0 0 1\n30001 60001 2\n";

        for (role_uids, role_gids) in [
            ([20_001, 20_003], TEST_ROLE_GIDS),
            (TEST_ROLE_UIDS, [30_001, 30_003]),
        ] {
            assert!(matches!(
                bind_current_credential_domain(
                    Some(user),
                    mount,
                    Some(uid_map),
                    Some(gid_map),
                    role_uids,
                    role_gids,
                ),
                Err(NativeCanaryFacilityError::Policy(
                    "reviewed canary role credentials are not live in the daemon ID-map domain"
                ))
            ));
        }
    }

    #[test]
    fn route_readback_diagnostic_names_only_drifting_fields() {
        let route = FacilityHostRoute {
            destination: IpAddr::V6("2606:4700:4700::f111".parse().expect("test IPv6")),
            output_interface: InterfaceIndex::new(73).expect("test interface"),
            table: RouteTableId::from_raw(20_254),
            protocol: RouteProtocol::from_raw(186),
            scope: facility_route_scope(NetworkAddressFamily::Ipv6),
            metric: NonZeroU32::new(1_031).expect("test route metric"),
        };
        let expected = expected_route_record(route).expect("expected test route");
        let actual = flux_core::NetworkRouteRecord::new(
            expected.destination(),
            expected.source(),
            expected.properties(),
            expected.priority() + 1,
            expected.path().clone(),
        )
        .expect("actual test route");
        let mut tracker = flux_core::NetworkInventoryTracker::new();
        let inventory = tracker
            .publish_complete_with_routing([], [], [actual], [])
            .expect("publish route diagnostic inventory")
            .clone();
        let actual = inventory.routes().iter().collect::<Vec<_>>();

        assert_eq!(
            route_readback_mismatch_fields(&inventory, &[expected], &actual),
            ["priority", "preference"]
        );
    }

    #[test]
    fn facility_route_scope_is_canonical_per_address_family() {
        assert_eq!(
            facility_route_scope(NetworkAddressFamily::Ipv4),
            RouteScope::from_raw(FACILITY_ROUTE_SCOPE_LINK)
        );
        assert_eq!(
            facility_route_scope(NetworkAddressFamily::Ipv6),
            RouteScope::from_raw(FACILITY_ROUTE_SCOPE_UNIVERSE)
        );
    }

    #[test]
    fn rule_readback_diagnostic_names_only_drifting_fields() {
        let rule = FacilityPeerRule {
            destination: IpAddr::V4(Ipv4Addr::new(9, 254, 254, 253)),
            engine_uid: NonZeroU32::new(2_900_002).expect("test engine UID"),
            transport_protocol: libc::IPPROTO_TCP as u8,
            destination_port: 61_001,
            priority: flux_core::RulePriority::from_raw(30_998),
            table: RuleTableId::from_raw(20_254),
            protocol: RuleProtocol::from_raw(186),
            proxy_mark_mask: NonZeroU32::new(0x0300_0000).expect("test proxy mask"),
        };
        let expected = expected_rule_record(rule).expect("expected test rule");
        let actual = flux_core::NetworkRuleRecord::new(
            expected.destination(),
            expected.source(),
            expected.properties(),
            expected.priority(),
            expected.goto_target(),
        )
        .expect("actual test rule")
        .with_fwmark(expected.fwmark().expect("test rule fwmark"))
        .with_uid_range(expected.uid_range().expect("test rule UID range"));

        assert_eq!(
            rule_readback_mismatch_fields(&[expected], &[&actual]),
            ["ip_protocol", "destination_port_range"]
        );
    }

    #[test]
    fn veth_request_nests_the_peer_ifinfomsg_names_and_namespace_descriptor() {
        let request =
            encode_veth_pair_request(b"fxcan0", b"fxcanp", 73).expect("encode veth request");
        assert_eq!(u16_at(&request, 4), RTM_NEWLINK);
        assert_eq!(u16_at(&request, 6), mutation_flags(true));
        assert_eq!(u32_at(&request, 0) as usize, request.len());

        let outer = attributes(&request[NLMSG_HEADER_LENGTH + IFINFO_MESSAGE_LENGTH..]);
        assert_eq!(attribute(&outer, IFLA_IFNAME), b"fxcan0\0");
        let link_info = attribute(&outer, IFLA_LINKINFO | NLA_F_NESTED);
        let link_info = attributes(link_info);
        assert_eq!(attribute(&link_info, IFLA_INFO_KIND), b"veth\0");
        let info_data = attribute(&link_info, IFLA_INFO_DATA | NLA_F_NESTED);
        let info_data = attributes(info_data);
        let peer = attribute(&info_data, VETH_INFO_PEER | NLA_F_NESTED);
        assert!(peer[..IFINFO_MESSAGE_LENGTH].iter().all(|byte| *byte == 0));
        let peer_attributes = attributes(&peer[IFINFO_MESSAGE_LENGTH..]);
        assert_eq!(attribute(&peer_attributes, IFLA_IFNAME), b"fxcanp\0");
        assert_eq!(
            attribute(&peer_attributes, IFLA_NET_NS_FD),
            73_i32.to_ne_bytes()
        );
    }

    #[test]
    fn peer_rule_request_uses_native_order_for_kernel_port_ranges() {
        let rule = FacilityPeerRule {
            destination: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            engine_uid: NonZeroU32::new(20_002).expect("engine UID"),
            transport_protocol: libc::IPPROTO_TCP as u8,
            destination_port: 0x1234,
            priority: flux_core::RulePriority::from_raw(30_998),
            table: RuleTableId::from_raw(20_254),
            protocol: RuleProtocol::from_raw(186),
            proxy_mark_mask: NonZeroU32::new(0x0300_0000).expect("proxy mask"),
        };
        let request = encode_peer_rule_request(rule, true).expect("encode peer rule");
        assert_eq!(u16_at(&request, 4), RTM_NEWRULE);
        assert_eq!(u16_at(&request, 6), mutation_flags(true));
        let attributes = attributes(&request[NLMSG_HEADER_LENGTH + ROUTE_MESSAGE_LENGTH..]);
        assert_eq!(attribute(&attributes, FRA_DST), [8, 8, 8, 8]);
        assert_eq!(
            attribute(&attributes, FRA_DPORT_RANGE),
            [0x1234_u16.to_ne_bytes(), 0x1234_u16.to_ne_bytes()].concat()
        );
        assert_eq!(
            attribute(&attributes, FRA_IP_PROTO),
            [libc::IPPROTO_TCP as u8]
        );
        assert_eq!(
            attribute(&attributes, FRA_UID_RANGE),
            [20_002_u32.to_ne_bytes(), 20_002_u32.to_ne_bytes()].concat()
        );
    }

    #[test]
    fn netlink_ack_requires_the_exact_kernel_sequence_and_success_status() {
        let mut ack = vec![0_u8; NLMSG_HEADER_LENGTH + 4];
        let length = u32::try_from(ack.len()).expect("ACK length");
        ack[0..4].copy_from_slice(&length.to_ne_bytes());
        ack[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        ack[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(decode_netlink_ack(&ack).is_ok());

        ack[8..12].copy_from_slice(&2_u32.to_ne_bytes());
        assert!(decode_netlink_ack(&ack).is_err());
        ack[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        ack[NLMSG_HEADER_LENGTH..].copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        assert!(matches!(
            decode_netlink_ack(&ack),
            Err(NativeCanaryFacilityError::System { source, .. })
                if source.raw_os_error() == Some(libc::EPERM)
        ));
    }

    #[test]
    fn exact_address_readback_rejects_unexpected_non_link_local_veth_addresses() {
        let interface = InterfaceIndex::new(101).expect("interface index");
        let ipv4 = IpAddr::V4(Ipv4Addr::new(9, 254, 254, 1));
        let link_local = IpAddr::V6("fe80::1".parse().expect("link-local IPv6"));
        let expected = address_inventory(interface, [(ipv4, 32), (link_local, 64)]);
        let other = address_inventory(InterfaceIndex::new(102).expect("other interface index"), []);
        validate_address_readback(&expected, &other, interface, ipv4, None)
            .expect("one expected host address plus one link-local address is exact");

        let unexpected = address_inventory(
            interface,
            [
                (ipv4, 32),
                (link_local, 64),
                (IpAddr::V4(Ipv4Addr::new(9, 254, 254, 9)), 32),
            ],
        );
        assert!(matches!(
            validate_address_readback(&unexpected, &other, interface, ipv4, None),
            Err(NativeCanaryFacilityError::Policy(
                "created canary veth carries an unexpected non-link-local address"
            ))
        ));
    }

    #[test]
    fn live_listener_collision_audit_rejects_an_owned_tcp_port() {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
            .expect("bind temporary wildcard listener");
        let tcp =
            std::num::NonZeroU16::new(listener.local_addr().expect("listener address").port())
                .expect("ephemeral listener port is nonzero");
        let dns = std::num::NonZeroU16::new(if tcp.get() == u16::MAX {
            tcp.get() - 1
        } else {
            tcp.get() + 1
        })
        .expect("adjacent DNS port is nonzero");
        let ports = CanaryResponderPorts::new(tcp, tcp, dns).expect("responder ports");

        assert!(
            !listener_ports_are_clear_values(ports, CanaryAddressFamilies::Ipv4Only)
                .expect("complete listener collision audit")
        );
    }

    #[test]
    fn facility_journal_recovery_is_exact_and_retires_only_proven_absence() {
        let directory = tempfile::tempdir().expect("temporary journal directory");
        let boot = BootIdentity::parse("00112233-4455-6677-8899-aabbccddeeff")
            .expect("journal boot identity");
        let other_boot = BootIdentity::parse("11223344-5566-7788-99aa-bbccddeeff00")
            .expect("other boot identity");
        let namespace = NetworkNamespaceIdentity::new(71, 72).expect("journal namespace");
        let other_namespace =
            NetworkNamespaceIdentity::new(81, 82).expect("other journal namespace");

        for (name, current_boot, current_namespace) in [
            ("same-owner.json", &boot, namespace),
            ("cross-boot.json", &other_boot, other_namespace),
        ] {
            let path = directory.path().join(name);
            let journal = test_facility_journal(&boot, namespace);
            persist_facility_journal(&path, &journal).expect("persist valid facility journal");
            recover_native_boot_canary_facility(&path, current_boot, current_namespace)
                .expect("exact absent journal recovers");
            assert!(!path.exists(), "proven-absent journal is retired");
        }
    }

    #[test]
    fn invalid_or_uncertain_facility_journals_remain_for_operator_recovery() {
        let directory = tempfile::tempdir().expect("temporary journal directory");
        let boot = BootIdentity::parse("00112233-4455-6677-8899-aabbccddeeff")
            .expect("journal boot identity");
        let other_boot = BootIdentity::parse("11223344-5566-7788-99aa-bbccddeeff00")
            .expect("other boot identity");
        let namespace = NetworkNamespaceIdentity::new(71, 72).expect("journal namespace");
        let other_namespace =
            NetworkNamespaceIdentity::new(81, 82).expect("other journal namespace");

        let invalid_path = directory.path().join("invalid.json");
        let mut invalid = test_facility_journal(&boot, namespace);
        invalid.schema_version = FACILITY_JOURNAL_SCHEMA_VERSION + 1;
        persist_facility_journal(&invalid_path, &invalid).expect("persist invalid journal bytes");
        assert!(
            recover_native_boot_canary_facility(&invalid_path, &other_boot, other_namespace)
                .is_err()
        );
        assert!(invalid_path.exists(), "invalid journal remains retained");

        let uncertain_path = directory.path().join("uncertain.json");
        let mut uncertain = test_facility_journal(&boot, namespace);
        uncertain.daemon_veth_name = b"lo".to_vec();
        persist_facility_journal(&uncertain_path, &uncertain)
            .expect("persist syntactically valid uncertain journal");
        assert!(
            recover_native_boot_canary_facility(&uncertain_path, &other_boot, other_namespace)
                .is_err()
        );
        assert!(
            uncertain_path.exists(),
            "unproven cross-boot absence retains cleanup authority"
        );
    }

    fn address_inventory<const N: usize>(
        interface: InterfaceIndex,
        addresses: [(IpAddr, u8); N],
    ) -> NetworkInventory {
        let addresses = addresses.map(|(address, prefix)| {
            flux_core::InterfaceAddressRecord::new(
                interface,
                address,
                prefix,
                InterfaceAddressFlags::default(),
            )
            .expect("test interface address")
        });
        let mut tracker = flux_core::NetworkInventoryTracker::new();
        tracker
            .publish_complete([], addresses)
            .expect("publish test address inventory")
            .clone()
    }

    fn test_facility_journal(
        boot: &BootIdentity,
        namespace: NetworkNamespaceIdentity,
    ) -> NativeCanaryFacilityJournalRecord {
        NativeCanaryFacilityJournalRecord {
            schema_version: FACILITY_JOURNAL_SCHEMA_VERSION,
            boot_identity: boot.as_str().to_owned(),
            daemon_network_namespace_device: namespace.device(),
            daemon_network_namespace_inode: namespace.inode(),
            reviewed_policy_digest: [0x41; 32],
            reviewed_policy_revision: 1,
            daemon_veth_name: b"fxjcan0".to_vec(),
            peer_veth_name: b"fxjcanp".to_vec(),
            daemon_ipv4: [9, 254, 254, 252],
            peer_ipv4: [9, 254, 254, 253],
            daemon_ipv6: None,
            peer_ipv6: None,
            tcp_echo_port: 61_001,
            udp_echo_port: 61_002,
            dns_port: 61_003,
            engine_uid: 20_002,
            proxy_rule_priority: 4_000_000_000,
            peer_rule_priority: 4_000_000_001,
            proxy_capture_table: 4_000_000_002,
            peer_table: 4_000_000_003,
            peer_return_table: 254,
            rule_protocol: 186,
            route_protocol: 186,
            route_metric: 1_031,
            proxy_mark_value: 0x0200_0000,
            proxy_mark_mask: 0x0300_0000,
        }
    }

    fn attributes(bytes: &[u8]) -> Vec<(u16, &[u8])> {
        let mut attributes = Vec::new();
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let length = usize::from(u16_at(bytes, offset));
            assert!(length >= NETLINK_ATTRIBUTE_HEADER_LENGTH);
            assert!(offset + length <= bytes.len());
            let kind = u16_at(bytes, offset + 2);
            attributes.push((kind, &bytes[offset + 4..offset + length]));
            offset += align4(length);
        }
        assert_eq!(offset, bytes.len());
        attributes
    }

    fn attribute<'a>(attributes: &'a [(u16, &'a [u8])], kind: u16) -> &'a [u8] {
        let matching = attributes
            .iter()
            .filter(|(observed, _)| *observed == kind)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        matching[0].1
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_ne_bytes(bytes[offset..offset + 2].try_into().expect("u16 bytes"))
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_ne_bytes(bytes[offset..offset + 4].try_into().expect("u32 bytes"))
    }
}
