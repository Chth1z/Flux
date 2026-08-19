use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use flux_core::{
    GenerationId, InterfaceIndex, InterfaceName, NetworkAddressFamily, RoutePrefix, RouteProtocol,
    RouteScope, RouteTableId, RouteType, RuleFwMark, RulePriority, RuleProtocol,
};
use sha2::{Digest, Sha256};

use crate::netlink::policy_routing::{
    ManagedPolicyRoutingIdentity, ManagedPolicyRoutingIdentityError,
    ManagedPolicyRoutingRecoveryRecord,
};

use super::super::super::owner_durable::{
    MAX_NATIVE_XTABLES_TARGET_ARCHIVE_BYTES, NativeXtablesDurableError, NativeXtablesDurableStore,
};
use super::super::super::{
    MAX_XTABLES_RESTORE_BYTES, MAX_XTABLES_RESTORE_CHAIN_BYTES, XtablesRestoreAction,
    XtablesRestoreArtifact, XtablesRestoreContext, XtablesRestoreFamily, XtablesRestoreParseError,
    parse_xtables_restore,
};
use super::super::XtablesStableFamilyRecoveryMaterial;
use super::{
    NativeCaptureTargetIdentity, NativePolicyRoutingAudit, NativePolicyRoutingAuditError,
    NativeXtablesAdmittedTarget, NativeXtablesConvergedState, NativeXtablesTargetError,
    NativeXtablesTargetIdentity, NativeXtablesTargetResolver, XtablesStableFamilyPlan,
    XtablesStableTopologyError, XtablesStableTopologyPlan,
};

const ARCHIVE_MAGIC: &[u8] = b"flux-native-xtables-target-archive\0";
const ARCHIVE_SCHEMA: u16 = 2;
const ARCHIVE_CHECKSUM_BYTES: usize = 32;
const MAX_ARCHIVE_TARGETS: usize = 2;
const MAX_PRIVATE_CHAINS_PER_FAMILY: usize = 8;
const MAX_STABLE_ARTIFACT_BYTES: usize = 64 * 1024;

/// Privacy-reduced validation result for one durable target archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesTargetArchiveObservation {
    present: bool,
    target_count: usize,
    digest: [u8; 32],
}

impl NativeXtablesTargetArchiveObservation {
    #[must_use]
    pub(crate) const fn present(self) -> bool {
        self.present
    }

    #[must_use]
    pub(crate) const fn target_count(self) -> usize {
        self.target_count
    }

    #[must_use]
    pub(crate) const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

pub(crate) fn observe_native_xtables_target_archive(
    encoded: Option<&[u8]>,
) -> Result<NativeXtablesTargetArchiveObservation, NativeXtablesTargetArchiveError> {
    let Some(encoded) = encoded else {
        return Ok(NativeXtablesTargetArchiveObservation {
            present: false,
            target_count: 0,
            digest: [0; 32],
        });
    };
    let targets = decode_archive(encoded)?;
    Ok(NativeXtablesTargetArchiveObservation {
        present: true,
        target_count: targets.len(),
        digest: Sha256::digest(encoded).into(),
    })
}

/// Requires a durable target archive to contain exactly the authenticated active target.
///
/// An active-owner census may retain this one archive, but it must not hide a replacement,
/// duplicate, or second target by filtering the decoded list. The archive parser already rejects
/// duplicate identities; this helper additionally rejects every non-singleton or mismatched list.
pub(crate) fn observe_native_xtables_target_archive_for_active_owner(
    encoded: Option<&[u8]>,
    active_target: NativeCaptureTargetIdentity,
) -> Result<(), NativeXtablesTargetArchiveError> {
    let Some(encoded) = encoded else {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "active owner target archive is absent",
        ));
    };
    let targets = decode_archive(encoded)?;
    let expected_target = NativeXtablesTargetIdentity {
        generation: active_target.generation(),
        target_digest: active_target.target_digest(),
        tool_digest: active_target.tool_digest(),
        routing_digest: active_target.routing_digest(),
    };
    if targets.len() != 1 || targets[0].identity() != expected_target {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "active owner target archive is not exactly the authenticated target",
        ));
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct DurableNativeXtablesTargetResolver {
    store: NativeXtablesDurableStore,
    targets: Arc<Mutex<Vec<NativeXtablesAdmittedTarget>>>,
}

impl DurableNativeXtablesTargetResolver {
    pub(crate) fn open(
        store: NativeXtablesDurableStore,
    ) -> Result<Self, NativeXtablesTargetArchiveError> {
        let targets = load_targets(&store)?;
        Ok(Self {
            store,
            targets: Arc::new(Mutex::new(targets)),
        })
    }

    pub(crate) fn refresh(&self) -> Result<(), NativeXtablesTargetArchiveError> {
        let mut guard = self.lock()?;
        *guard = load_targets(&self.store)?;
        Ok(())
    }

    pub(crate) fn stage(
        &self,
        target: NativeXtablesAdmittedTarget,
    ) -> Result<(), NativeXtablesTargetArchiveError> {
        let mut guard = self.lock()?;
        let mut next = guard.clone();
        if let Some(existing) = next
            .iter_mut()
            .find(|existing| existing.identity() == target.identity())
        {
            *existing = target;
        } else {
            next.push(target);
        }
        next.sort_by_key(NativeXtablesAdmittedTarget::identity);
        if next.len() > MAX_ARCHIVE_TARGETS {
            return Err(NativeXtablesTargetArchiveError::CapacityExceeded);
        }
        self.persist(&next)?;
        *guard = next;
        Ok(())
    }

    pub(crate) fn retain_state(
        &self,
        state: NativeXtablesConvergedState,
    ) -> Result<(), NativeXtablesTargetArchiveError> {
        let mut guard = self.lock()?;
        let next = match state {
            NativeXtablesConvergedState::Active(identity) => vec![
                guard
                    .iter()
                    .find(|target| target.identity() == identity)
                    .cloned()
                    .ok_or(NativeXtablesTargetArchiveError::MissingSettledTarget)?,
            ],
            NativeXtablesConvergedState::CleanAbsent => Vec::new(),
        };
        self.persist(&next)?;
        *guard = next;
        Ok(())
    }

    pub(crate) fn identities(
        &self,
    ) -> Result<Vec<NativeXtablesTargetIdentity>, NativeXtablesTargetArchiveError> {
        Ok(self
            .lock()?
            .iter()
            .map(NativeXtablesAdmittedTarget::identity)
            .collect())
    }

    pub(crate) fn recovery_routing_audit(
        &self,
    ) -> Result<Option<NativePolicyRoutingAudit>, NativeXtablesTargetArchiveError> {
        let guard = self.lock()?;
        let Some(first) = guard.first().map(|target| *target.routing_audit()) else {
            return Ok(None);
        };
        if guard.iter().any(|target| target.routing_audit() != &first) {
            return Err(NativeXtablesTargetArchiveError::Invalid(
                "retained targets disagree on the recovery routing audit",
            ));
        }
        Ok(Some(first))
    }

    fn persist(
        &self,
        targets: &[NativeXtablesAdmittedTarget],
    ) -> Result<(), NativeXtablesTargetArchiveError> {
        let encoded = encode_archive(targets)?;
        self.store
            .persist_target_archive(&encoded)
            .map_err(NativeXtablesTargetArchiveError::Durable)
    }

    fn lock(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, Vec<NativeXtablesAdmittedTarget>>,
        NativeXtablesTargetArchiveError,
    > {
        self.targets
            .lock()
            .map_err(|_| NativeXtablesTargetArchiveError::LockPoisoned)
    }
}

fn load_targets(
    store: &NativeXtablesDurableStore,
) -> Result<Vec<NativeXtablesAdmittedTarget>, NativeXtablesTargetArchiveError> {
    store
        .load_target_archive()
        .map_err(NativeXtablesTargetArchiveError::Durable)?
        .map(|encoded| decode_archive(&encoded))
        .transpose()
        .map(Option::unwrap_or_default)
}

impl NativeXtablesTargetResolver for DurableNativeXtablesTargetResolver {
    fn resolve(
        &mut self,
        identity: NativeXtablesTargetIdentity,
    ) -> Result<NativeXtablesAdmittedTarget, Box<str>> {
        self.targets
            .lock()
            .map_err(|_| Box::<str>::from("native target archive lock is poisoned"))?
            .iter()
            .find(|target| target.identity() == identity)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "exact target material for generation {} is absent",
                    identity.generation().get()
                )
                .into_boxed_str()
            })
    }
}

#[derive(Debug)]
pub(crate) enum NativeXtablesTargetArchiveError {
    Durable(NativeXtablesDurableError),
    Invalid(&'static str),
    InvalidRestore {
        slot: &'static str,
        source: XtablesRestoreParseError,
    },
    InvalidTopology(XtablesStableTopologyError),
    InvalidRouting(ManagedPolicyRoutingIdentityError),
    InvalidRoutingAudit(NativePolicyRoutingAuditError),
    InvalidTarget(NativeXtablesTargetError),
    CapacityExceeded,
    MissingSettledTarget,
    LockPoisoned,
}

impl fmt::Display for NativeXtablesTargetArchiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Durable(source) => {
                write!(formatter, "native target archive I/O failed: {source}")
            }
            Self::Invalid(reason) => write!(formatter, "invalid native target archive: {reason}"),
            Self::InvalidRestore { slot, source } => {
                write!(
                    formatter,
                    "invalid native target archive {slot} artifact: {source}"
                )
            }
            Self::InvalidTopology(source) => {
                write!(
                    formatter,
                    "invalid native target archive topology: {source}"
                )
            }
            Self::InvalidRouting(source) => {
                write!(formatter, "invalid native target archive routing: {source}")
            }
            Self::InvalidRoutingAudit(source) => {
                write!(
                    formatter,
                    "invalid native target archive routing audit: {source}"
                )
            }
            Self::InvalidTarget(source) => {
                write!(formatter, "invalid native target archive target: {source}")
            }
            Self::CapacityExceeded => formatter.write_str(
                "native target archive cannot retain more than active and replacement targets",
            ),
            Self::MissingSettledTarget => {
                formatter.write_str("settled native owner state is absent from the target archive")
            }
            Self::LockPoisoned => formatter.write_str("native target archive lock is poisoned"),
        }
    }
}

impl Error for NativeXtablesTargetArchiveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Durable(source) => Some(source),
            Self::InvalidRestore { source, .. } => Some(source),
            Self::InvalidTopology(source) => Some(source),
            Self::InvalidRouting(source) => Some(source),
            Self::InvalidRoutingAudit(source) => Some(source),
            Self::InvalidTarget(source) => Some(source),
            Self::Invalid(_)
            | Self::CapacityExceeded
            | Self::MissingSettledTarget
            | Self::LockPoisoned => None,
        }
    }
}

fn encode_archive(
    targets: &[NativeXtablesAdmittedTarget],
) -> Result<Vec<u8>, NativeXtablesTargetArchiveError> {
    if targets.len() > MAX_ARCHIVE_TARGETS {
        return Err(NativeXtablesTargetArchiveError::CapacityExceeded);
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(ARCHIVE_MAGIC);
    put_u16(&mut encoded, ARCHIVE_SCHEMA);
    put_u8(&mut encoded, checked_u8(targets.len())?);
    for target in targets {
        encode_target(&mut encoded, target)?;
    }
    let checksum = Sha256::digest(&encoded);
    encoded.extend_from_slice(&checksum);
    if encoded.len() > MAX_NATIVE_XTABLES_TARGET_ARCHIVE_BYTES {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "encoded target material exceeds the durable archive bound",
        ));
    }
    Ok(encoded)
}

fn decode_archive(
    encoded: &[u8],
) -> Result<Vec<NativeXtablesAdmittedTarget>, NativeXtablesTargetArchiveError> {
    if encoded.len() > MAX_NATIVE_XTABLES_TARGET_ARCHIVE_BYTES
        || encoded.len() < ARCHIVE_MAGIC.len() + 2 + 1 + ARCHIVE_CHECKSUM_BYTES
    {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "archive length is outside the canonical bound",
        ));
    }
    let body_length = encoded.len() - ARCHIVE_CHECKSUM_BYTES;
    let (body, stored_checksum) = encoded.split_at(body_length);
    if Sha256::digest(body).as_slice() != stored_checksum {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "archive checksum does not match",
        ));
    }
    let mut cursor = Cursor::new(body);
    if cursor.take(ARCHIVE_MAGIC.len())? != ARCHIVE_MAGIC {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "archive magic does not match",
        ));
    }
    if cursor.u16()? != ARCHIVE_SCHEMA {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "archive schema is unsupported",
        ));
    }
    let count = usize::from(cursor.u8()?);
    if count > MAX_ARCHIVE_TARGETS {
        return Err(NativeXtablesTargetArchiveError::CapacityExceeded);
    }
    let mut targets = Vec::with_capacity(count);
    for _ in 0..count {
        targets.push(decode_target(&mut cursor)?);
    }
    if !cursor.is_empty() {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "archive contains trailing bytes",
        ));
    }
    targets.sort_by_key(NativeXtablesAdmittedTarget::identity);
    if targets
        .windows(2)
        .any(|pair| pair[0].identity() == pair[1].identity())
    {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "archive repeats a target identity",
        ));
    }
    Ok(targets)
}

fn encode_target(
    encoded: &mut Vec<u8>,
    target: &NativeXtablesAdmittedTarget,
) -> Result<(), NativeXtablesTargetArchiveError> {
    let identity = target.identity();
    put_u32(encoded, identity.generation().get());
    encoded.extend_from_slice(&identity.target_digest());
    encoded.extend_from_slice(&target.source_artifact_digest());
    encoded.extend_from_slice(&identity.tool_digest());
    encoded.extend_from_slice(&identity.routing_digest());

    put_u8(encoded, checked_u8(target.topology().families().len())?);
    for family in target.topology().families() {
        encode_family(encoded, family)?;
    }
    put_u8(encoded, checked_u8(target.routing().len())?);
    for routing in target.routing() {
        encode_routing(encoded, *routing)?;
    }
    for routing in target.routing_audit().identities() {
        encode_routing(encoded, *routing)?;
    }
    Ok(())
}

fn decode_target(
    cursor: &mut Cursor<'_>,
) -> Result<NativeXtablesAdmittedTarget, NativeXtablesTargetArchiveError> {
    let generation = GenerationId::new(cursor.u32()?).ok_or(
        NativeXtablesTargetArchiveError::Invalid("target generation is zero"),
    )?;
    let target_digest = cursor.array()?;
    let source_artifact_digest = cursor.array()?;
    let identity = NativeXtablesTargetIdentity {
        generation,
        target_digest,
        tool_digest: cursor.array()?,
        routing_digest: cursor.array()?,
    };
    let family_count = usize::from(cursor.u8()?);
    if !(1..=2).contains(&family_count) {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "target must contain one or two family plans",
        ));
    }
    let mut families = Vec::with_capacity(family_count);
    for _ in 0..family_count {
        families.push(decode_family(cursor)?);
    }
    let topology = XtablesStableTopologyPlan::from_recovery(families)
        .map_err(NativeXtablesTargetArchiveError::InvalidTopology)?;

    let routing_count = usize::from(cursor.u8()?);
    if routing_count > 2 {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "target contains too many active routing identities",
        ));
    }
    let mut routing = Vec::with_capacity(routing_count);
    for _ in 0..routing_count {
        routing.push(decode_routing(cursor)?);
    }
    let routing_audit =
        NativePolicyRoutingAudit::new([decode_routing(cursor)?, decode_routing(cursor)?])
            .map_err(NativeXtablesTargetArchiveError::InvalidRoutingAudit)?;
    NativeXtablesAdmittedTarget::from_recovery(
        identity,
        source_artifact_digest,
        topology,
        routing,
        routing_audit,
    )
    .map_err(NativeXtablesTargetArchiveError::InvalidTarget)
}

fn encode_family(
    encoded: &mut Vec<u8>,
    family: &XtablesStableFamilyPlan,
) -> Result<(), NativeXtablesTargetArchiveError> {
    put_u8(encoded, family_tag(family.family()));
    put_u8(encoded, checked_u8(family.private_chains().len())?);
    for chain in family.private_chains() {
        put_text(encoded, chain)?;
    }
    put_optional_text(encoded, family.prerouting_root())?;
    put_optional_text(encoded, family.output_root())?;
    put_artifact(encoded, family.prepare())?;
    put_artifact(encoded, family.retire())?;
    put_artifact(encoded, family.install())?;
    put_artifact(encoded, family.switch())?;
    match family.detach_output() {
        Some(artifact) => {
            put_u8(encoded, 1);
            put_artifact(encoded, artifact)?;
        }
        None => put_u8(encoded, 0),
    }
    put_artifact(encoded, family.detach_remaining())?;
    Ok(())
}

fn decode_family(
    cursor: &mut Cursor<'_>,
) -> Result<XtablesStableFamilyPlan, NativeXtablesTargetArchiveError> {
    let family = decode_family_tag(cursor.u8()?)?;
    let chain_count = usize::from(cursor.u8()?);
    if !(1..=MAX_PRIVATE_CHAINS_PER_FAMILY).contains(&chain_count) {
        return Err(NativeXtablesTargetArchiveError::Invalid(
            "private chain count is outside the canonical bound",
        ));
    }
    let mut private_chains = Vec::with_capacity(chain_count);
    for _ in 0..chain_count {
        private_chains.push(cursor.text(MAX_XTABLES_RESTORE_CHAIN_BYTES)?);
    }
    let prerouting_root = cursor.optional_text(MAX_XTABLES_RESTORE_CHAIN_BYTES)?;
    let output_root = cursor.optional_text(MAX_XTABLES_RESTORE_CHAIN_BYTES)?;
    let prepare = cursor.artifact(
        family,
        XtablesRestoreAction::Apply,
        MAX_XTABLES_RESTORE_BYTES,
        "prepare",
    )?;
    let retire = cursor.artifact(
        family,
        XtablesRestoreAction::Cleanup,
        MAX_XTABLES_RESTORE_BYTES,
        "retire",
    )?;
    let install = cursor.artifact(
        family,
        XtablesRestoreAction::Apply,
        MAX_STABLE_ARTIFACT_BYTES,
        "install",
    )?;
    let switch = cursor.artifact(
        family,
        XtablesRestoreAction::Replace,
        MAX_STABLE_ARTIFACT_BYTES,
        "switch",
    )?;
    let detach_output = match cursor.u8()? {
        0 => None,
        1 => Some(cursor.artifact(
            family,
            XtablesRestoreAction::Cleanup,
            MAX_STABLE_ARTIFACT_BYTES,
            "detach output",
        )?),
        _ => {
            return Err(NativeXtablesTargetArchiveError::Invalid(
                "optional artifact tag is not canonical",
            ));
        }
    };
    let detach_remaining = cursor.artifact(
        family,
        XtablesRestoreAction::Cleanup,
        MAX_STABLE_ARTIFACT_BYTES,
        "detach remaining",
    )?;
    XtablesStableFamilyPlan::from_recovery(XtablesStableFamilyRecoveryMaterial {
        family,
        private_chains: private_chains.into_boxed_slice(),
        prerouting_root,
        output_root,
        prepare,
        retire,
        install,
        switch,
        detach_output,
        detach_remaining,
    })
    .map_err(NativeXtablesTargetArchiveError::InvalidTopology)
}

fn encode_routing(
    encoded: &mut Vec<u8>,
    identity: ManagedPolicyRoutingIdentity,
) -> Result<(), NativeXtablesTargetArchiveError> {
    let record = identity.recovery_record();
    put_u8(encoded, network_family_tag(record.family));
    put_text_bytes(encoded, record.loopback_name.as_bytes())?;
    put_u32(encoded, record.loopback_index.get());
    put_ip(encoded, record.destination.address());
    put_u8(encoded, record.destination.prefix_length());
    put_u32(encoded, record.route_table.get());
    put_u8(encoded, record.route_protocol.raw());
    put_u8(encoded, record.route_scope.raw());
    put_u8(encoded, record.route_type.raw());
    put_u32(encoded, record.route_metric.get());
    put_u32(encoded, record.output_interface.get());
    put_u32(encoded, record.rule_priority.get());
    put_u32(encoded, record.rule_table.get());
    put_u32(encoded, record.mark.value());
    put_u32(encoded, record.mark.mask());
    put_u8(encoded, record.rule_protocol.raw());
    Ok(())
}

fn decode_routing(
    cursor: &mut Cursor<'_>,
) -> Result<ManagedPolicyRoutingIdentity, NativeXtablesTargetArchiveError> {
    let family = decode_network_family_tag(cursor.u8()?)?;
    let loopback_name = InterfaceName::new(cursor.bytes(u8::MAX as usize)?).ok_or(
        NativeXtablesTargetArchiveError::Invalid("routing interface name is invalid"),
    )?;
    let loopback_index = InterfaceIndex::new(cursor.u32()?).ok_or(
        NativeXtablesTargetArchiveError::Invalid("routing loopback index is invalid"),
    )?;
    let destination = RoutePrefix::new(cursor.ip()?, cursor.u8()?).map_err(|_| {
        NativeXtablesTargetArchiveError::Invalid("routing destination prefix is invalid")
    })?;
    let route_table = RouteTableId::from_raw(cursor.u32()?);
    let route_protocol = RouteProtocol::from_raw(cursor.u8()?);
    let route_scope = RouteScope::from_raw(cursor.u8()?);
    let route_type = RouteType::from_raw(cursor.u8()?);
    let route_metric = NonZeroU32::new(cursor.u32()?).ok_or(
        NativeXtablesTargetArchiveError::Invalid("routing metric is zero"),
    )?;
    let output_interface = InterfaceIndex::new(cursor.u32()?).ok_or(
        NativeXtablesTargetArchiveError::Invalid("routing output interface is invalid"),
    )?;
    let rule_priority = RulePriority::from_raw(cursor.u32()?);
    let rule_table = RouteTableId::from_raw(cursor.u32()?);
    let mark = RuleFwMark::new(cursor.u32()?, cursor.u32()?).ok_or(
        NativeXtablesTargetArchiveError::Invalid("routing mark is semantically empty"),
    )?;
    let rule_protocol = RuleProtocol::from_raw(cursor.u8()?);
    ManagedPolicyRoutingIdentity::from_recovery(ManagedPolicyRoutingRecoveryRecord {
        family,
        loopback_name,
        loopback_index,
        destination,
        route_table,
        route_protocol,
        route_scope,
        route_type,
        route_metric,
        output_interface,
        rule_priority,
        rule_table,
        mark,
        rule_protocol,
    })
    .map_err(NativeXtablesTargetArchiveError::InvalidRouting)
}

fn put_artifact(
    encoded: &mut Vec<u8>,
    artifact: &XtablesRestoreArtifact,
) -> Result<(), NativeXtablesTargetArchiveError> {
    let bytes = artifact.render_canonical();
    put_bytes(encoded, &bytes)
}

fn put_optional_text(
    encoded: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), NativeXtablesTargetArchiveError> {
    match value {
        Some(value) => {
            put_u8(encoded, 1);
            put_text(encoded, value)
        }
        None => {
            put_u8(encoded, 0);
            Ok(())
        }
    }
}

fn put_text(encoded: &mut Vec<u8>, value: &str) -> Result<(), NativeXtablesTargetArchiveError> {
    put_text_bytes(encoded, value.as_bytes())
}

fn put_text_bytes(
    encoded: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), NativeXtablesTargetArchiveError> {
    put_u8(encoded, checked_u8(value.len())?);
    encoded.extend_from_slice(value);
    Ok(())
}

fn put_bytes(encoded: &mut Vec<u8>, value: &[u8]) -> Result<(), NativeXtablesTargetArchiveError> {
    put_u32(
        encoded,
        u32::try_from(value.len()).map_err(|_| {
            NativeXtablesTargetArchiveError::Invalid("artifact length does not fit u32")
        })?,
    );
    encoded.extend_from_slice(value);
    Ok(())
}

fn put_ip(encoded: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(address) => {
            put_u8(encoded, 4);
            encoded.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            put_u8(encoded, 6);
            encoded.extend_from_slice(&address.octets());
        }
    }
}

fn put_u8(encoded: &mut Vec<u8>, value: u8) {
    encoded.push(value);
}

fn put_u16(encoded: &mut Vec<u8>, value: u16) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(encoded: &mut Vec<u8>, value: u32) {
    encoded.extend_from_slice(&value.to_be_bytes());
}

fn checked_u8(value: usize) -> Result<u8, NativeXtablesTargetArchiveError> {
    u8::try_from(value).map_err(|_| {
        NativeXtablesTargetArchiveError::Invalid("archive collection length does not fit u8")
    })
}

const fn family_tag(family: XtablesRestoreFamily) -> u8 {
    match family {
        XtablesRestoreFamily::Ipv4 => 4,
        XtablesRestoreFamily::Ipv6 => 6,
    }
}

fn decode_family_tag(tag: u8) -> Result<XtablesRestoreFamily, NativeXtablesTargetArchiveError> {
    match tag {
        4 => Ok(XtablesRestoreFamily::Ipv4),
        6 => Ok(XtablesRestoreFamily::Ipv6),
        _ => Err(NativeXtablesTargetArchiveError::Invalid(
            "restore family tag is invalid",
        )),
    }
}

const fn network_family_tag(family: NetworkAddressFamily) -> u8 {
    match family {
        NetworkAddressFamily::Ipv4 => 4,
        NetworkAddressFamily::Ipv6 => 6,
    }
}

fn decode_network_family_tag(
    tag: u8,
) -> Result<NetworkAddressFamily, NativeXtablesTargetArchiveError> {
    match tag {
        4 => Ok(NetworkAddressFamily::Ipv4),
        6 => Ok(NetworkAddressFamily::Ipv6),
        _ => Err(NativeXtablesTargetArchiveError::Invalid(
            "routing family tag is invalid",
        )),
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], NativeXtablesTargetArchiveError> {
        if length > self.remaining.len() {
            return Err(NativeXtablesTargetArchiveError::Invalid(
                "archive ended before a complete field",
            ));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], NativeXtablesTargetArchiveError> {
        self.take(N)?
            .try_into()
            .map_err(|_| NativeXtablesTargetArchiveError::Invalid("fixed field length is invalid"))
    }

    fn u8(&mut self) -> Result<u8, NativeXtablesTargetArchiveError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, NativeXtablesTargetArchiveError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, NativeXtablesTargetArchiveError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], NativeXtablesTargetArchiveError> {
        let length = usize::from(self.u8()?);
        if length == 0 || length > maximum {
            return Err(NativeXtablesTargetArchiveError::Invalid(
                "length-prefixed text is outside its canonical bound",
            ));
        }
        self.take(length)
    }

    fn text(&mut self, maximum: usize) -> Result<Box<str>, NativeXtablesTargetArchiveError> {
        std::str::from_utf8(self.bytes(maximum)?)
            .map(Box::<str>::from)
            .map_err(|_| NativeXtablesTargetArchiveError::Invalid("archive text is not UTF-8"))
    }

    fn optional_text(
        &mut self,
        maximum: usize,
    ) -> Result<Option<Box<str>>, NativeXtablesTargetArchiveError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.text(maximum).map(Some),
            _ => Err(NativeXtablesTargetArchiveError::Invalid(
                "optional text tag is not canonical",
            )),
        }
    }

    fn artifact(
        &mut self,
        family: XtablesRestoreFamily,
        action: XtablesRestoreAction,
        maximum: usize,
        slot: &'static str,
    ) -> Result<XtablesRestoreArtifact, NativeXtablesTargetArchiveError> {
        let length = usize::try_from(self.u32()?).expect("u32 fits usize on supported targets");
        if length == 0 || length > maximum {
            return Err(NativeXtablesTargetArchiveError::Invalid(
                "restore artifact length is outside its slot bound",
            ));
        }
        parse_xtables_restore(
            self.take(length)?,
            XtablesRestoreContext::new(action, family),
        )
        .map_err(|source| NativeXtablesTargetArchiveError::InvalidRestore { slot, source })
    }

    fn ip(&mut self) -> Result<IpAddr, NativeXtablesTargetArchiveError> {
        match self.u8()? {
            4 => Ok(IpAddr::V4(Ipv4Addr::from(self.array::<4>()?))),
            6 => Ok(IpAddr::V6(Ipv6Addr::from(self.array::<16>()?))),
            _ => Err(NativeXtablesTargetArchiveError::Invalid(
                "IP address family tag is invalid",
            )),
        }
    }
}
