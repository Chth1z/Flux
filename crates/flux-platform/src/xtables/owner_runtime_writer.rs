use std::error::Error;
use std::fmt;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
use std::ffi::{CStr, CString};
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
use std::fs::File;
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
use std::os::unix::fs::MetadataExt;

use flux_core::{
    AddressHostFamilySelection, AndroidMarkDevicePolicyIdentity, AndroidMarkDevicePolicyRevision,
    AndroidMarkPlanningAuthority, AndroidTproxyTrafficDomainRequest, BootIdentity, FwmarkCandidate,
    InterfaceIndex, NetworkAddressFamily, NetworkNamespaceIdentity, OwnershipJournalIdentity,
    RouteProtocol, RouteTableId, RpdbFamilyPlacement, RpdbPlacementLease, RuleProtocol,
};
use sha2::{Digest, Sha256};

use super::{
    DurableNativeXtablesTargetResolver, NativePolicyRoutingAudit, NativeXtablesAdmittedTarget,
    NativeXtablesConvergedState, NativeXtablesConvergenceReport, NativeXtablesDesiredTarget,
    NativeXtablesEnvironment, NativeXtablesOwner, NativeXtablesOwnerAdapter,
    NativeXtablesOwnerError, NativeXtablesProcessOwnerAdapter, NativeXtablesTargetArchiveError,
    NativeXtablesTargetIdentity,
};
use crate::netlink::policy_routing::ManagedPolicyRoutingIdentity;
use crate::xtables::native::{
    XtablesRestoreProcessConfig, XtablesRestoreProcessError, XtablesToolSetProcessAdapter,
};
use crate::xtables::owner_durable::{
    NativeXtablesDurableError, NativeXtablesDurableStore, NativeXtablesRuntimeGuard,
};
use crate::xtables::{
    NativeCaptureConvergedState, NativeCaptureConvergence, NativeCaptureConvergenceReport,
    NativeCaptureDesired, NativeCaptureTargetIdentity, XtablesCaptureArtifactSet,
    XtablesLocalOutputRoutingSpec, XtablesLocalOutputRoutingTarget, XtablesRestoreFamily,
};

const NATIVE_ROUTE_METRIC: u32 = 1_024;
const NATIVE_ROUTE_PROTOCOL: u8 = 4;
const NATIVE_RULE_PROTOCOL: u8 = 99;
const ANDROID_RECOVERY_JOURNAL_IDENTITY_DOMAIN: &[u8] =
    b"Flux native Android recovery journal identity\0sha256-v1\0";

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
const NS_GET_USERNS: libc::c_ulong = 0xb701;

/// Builds the canonical, non-authorizing local-OUTPUT routing plan used by both lowering and
/// platform admission.
pub fn plan_native_xtables_local_output_routing(
    placement: RpdbPlacementLease,
    families: AddressHostFamilySelection,
) -> Result<XtablesLocalOutputRoutingSpec, NativeXtablesRoutingPlanError> {
    let mut targets = [None, None];
    for (index, family) in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6]
        .into_iter()
        .enumerate()
    {
        let family_placement = placement.family(family);
        if families.includes(family) && family_placement.is_none() {
            return Err(NativeXtablesRoutingPlanError::FamilyMismatch { family });
        }
        targets[index] = families
            .includes(family)
            .then(|| family_placement.map(canonical_routing_target))
            .flatten();
    }
    XtablesLocalOutputRoutingSpec::new(targets[0], targets[1])
        .map_err(|_| NativeXtablesRoutingPlanError::NoEnabledFamilies)
}

fn canonical_routing_target(placement: RpdbFamilyPlacement) -> XtablesLocalOutputRoutingTarget {
    XtablesLocalOutputRoutingTarget::new(
        placement.proxy_priority(),
        RouteTableId::from_raw(placement.private_table().get()),
        NonZeroU32::new(NATIVE_ROUTE_METRIC).expect("native route metric is nonzero"),
        RouteProtocol::from_raw(NATIVE_ROUTE_PROTOCOL),
        RuleProtocol::from_raw(NATIVE_RULE_PROTOCOL),
    )
    .expect("reviewed native routing constants and placement are structurally valid")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeXtablesRoutingPlanError {
    FamilyMismatch { family: NetworkAddressFamily },
    NoEnabledFamilies,
}

impl fmt::Display for NativeXtablesRoutingPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FamilyMismatch { family } => write!(
                formatter,
                "RPDB placement does not match the enabled {family:?} capture family"
            ),
            Self::NoEnabledFamilies => {
                formatter.write_str("native local-OUTPUT routing enables no address family")
            }
        }
    }
}

impl Error for NativeXtablesRoutingPlanError {}

/// Fixed process and durable-state paths for the production Android xtables owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeXtablesAndroidRuntimeConfig {
    tool_root: PathBuf,
    durable_root: PathBuf,
    require_ipv6: bool,
    wait_seconds: u16,
    timeout: Duration,
}

impl NativeXtablesAndroidRuntimeConfig {
    #[must_use]
    pub fn new(
        tool_root: impl AsRef<Path>,
        durable_root: impl AsRef<Path>,
        require_ipv6: bool,
        wait_seconds: u16,
        timeout: Duration,
    ) -> Self {
        Self {
            tool_root: tool_root.as_ref().to_owned(),
            durable_root: durable_root.as_ref().to_owned(),
            require_ipv6,
            wait_seconds,
            timeout,
        }
    }
}

/// Matched Android admission and convergence capabilities created from one reviewed authority.
pub struct NativeXtablesAndroidRuntime {
    admission: NativeXtablesCaptureAdmission,
    convergence: NativeXtablesCaptureConverger,
}

impl NativeXtablesAndroidRuntime {
    pub fn compose(
        config: NativeXtablesAndroidRuntimeConfig,
        authority: &AndroidMarkPlanningAuthority,
        placement: RpdbPlacementLease,
    ) -> Result<Self, NativeXtablesAndroidRuntimeError> {
        let routing_audit = android_routing_audit(authority, placement).map_err(|source| {
            NativeXtablesAndroidRuntimeError::new("bind Android routing", source)
        })?;
        let process = XtablesRestoreProcessConfig::new(config.wait_seconds, config.timeout)
            .map_err(|source| {
                NativeXtablesAndroidRuntimeError::new("configure xtables restore", source)
            })?;
        let tools = XtablesToolSetProcessAdapter::discover_standard(
            &config.tool_root,
            config.require_ipv6,
            process,
        )
        .map_err(|source| {
            NativeXtablesAndroidRuntimeError::new("discover xtables tools", source)
        })?;
        let tool_digest = *tools.identity().digest().as_bytes();
        let binding = NativeXtablesAndroidRuntimeBinding::new(authority, routing_audit);
        let environment = NativeXtablesEnvironment::new(
            binding.boot_identity.clone(),
            binding.network_namespace,
            binding.journal_identity,
            routing_audit,
        );
        let writer = NativeXtablesRuntimeWriter::new(
            NativeXtablesProcessOwnerAdapter::new(tools),
            NativeXtablesDurableStore::new(config.durable_root),
            environment,
        )
        .map_err(|source| {
            NativeXtablesAndroidRuntimeError::new("open native xtables owner", source)
        })?;
        Ok(Self {
            admission: NativeXtablesCaptureAdmission::new(tool_digest, binding),
            convergence: NativeXtablesCaptureConverger::from_runtime_writer(writer),
        })
    }

    /// Reconstructs a recovery-only converger from exact durable target material.
    ///
    /// This constructor grants no target admission. It is intended for startup and offline cleanup
    /// before a fresh clean-state census can mint a new planning authority.
    pub fn compose_recovery(
        config: NativeXtablesAndroidRuntimeConfig,
        current_boot_identity: BootIdentity,
        current_network_namespace: NetworkNamespaceIdentity,
    ) -> Result<Option<NativeXtablesCaptureConverger>, NativeXtablesAndroidRuntimeError> {
        let process = XtablesRestoreProcessConfig::new(config.wait_seconds, config.timeout)
            .map_err(|source| {
                NativeXtablesAndroidRuntimeError::new("configure recovery xtables restore", source)
            })?;
        let tools = XtablesToolSetProcessAdapter::discover_standard(
            &config.tool_root,
            config.require_ipv6,
            process,
        )
        .map_err(|source| {
            NativeXtablesAndroidRuntimeError::new("discover recovery xtables tools", source)
        })?;
        let tool_digest = *tools.identity().digest().as_bytes();
        let durable = NativeXtablesDurableStore::new(&config.durable_root);
        let resolver =
            DurableNativeXtablesTargetResolver::open(durable.clone()).map_err(|source| {
                NativeXtablesAndroidRuntimeError::new("open native recovery target archive", source)
            })?;
        let Some(routing_audit) = resolver.recovery_routing_audit().map_err(|source| {
            NativeXtablesAndroidRuntimeError::new("bind native recovery routing", source)
        })?
        else {
            let observed = durable.observe_read_only().map_err(|source| {
                NativeXtablesAndroidRuntimeError::new("inspect native recovery state", source)
            })?;
            if observed.journal_present()
                || observed.lease_present()
                || observed.writer_lock_present()
            {
                return Err(NativeXtablesAndroidRuntimeError::new(
                    "bind native recovery target",
                    NativeXtablesAndroidRecoveryBindingError::MissingTargetMaterial,
                ));
            }
            return Ok(None);
        };
        let journal_identity = recovery_journal_identity(
            &durable,
            &current_boot_identity,
            current_network_namespace,
            &config.durable_root,
            tool_digest,
        )
        .map_err(|source| {
            NativeXtablesAndroidRuntimeError::new("bind native recovery owner", source)
        })?;
        let environment = NativeXtablesEnvironment::new(
            current_boot_identity,
            current_network_namespace,
            journal_identity,
            routing_audit,
        );
        let writer = NativeXtablesRuntimeWriter::new(
            NativeXtablesProcessOwnerAdapter::new(tools),
            durable,
            environment,
        )
        .map_err(|source| {
            NativeXtablesAndroidRuntimeError::new("open native recovery owner", source)
        })?;
        Ok(Some(NativeXtablesCaptureConverger::from_runtime_writer(
            writer,
        )))
    }

    #[must_use]
    pub fn into_parts(self) -> (NativeXtablesCaptureAdmission, NativeXtablesCaptureConverger) {
        (self.admission, self.convergence)
    }
}

fn recovery_journal_identity(
    durable: &NativeXtablesDurableStore,
    current_boot_identity: &BootIdentity,
    current_network_namespace: NetworkNamespaceIdentity,
    durable_root: &Path,
    tool_digest: [u8; 32],
) -> Result<OwnershipJournalIdentity, NativeXtablesAndroidRecoveryBindingError> {
    if let Some(journal) = durable
        .load_journal()
        .map_err(NativeXtablesAndroidRecoveryBindingError::Durable)?
    {
        let binding = journal.binding();
        if binding.boot_identity() == current_boot_identity
            && binding.network_namespace() != current_network_namespace
        {
            return Err(NativeXtablesAndroidRecoveryBindingError::CurrentNamespaceMismatch);
        }
        return Ok(binding.journal_identity());
    }
    if let Some(lease) = durable
        .load_lease()
        .map_err(NativeXtablesAndroidRecoveryBindingError::Durable)?
    {
        if lease.boot_identity() == current_boot_identity
            && lease.network_namespace() != current_network_namespace
        {
            return Err(NativeXtablesAndroidRecoveryBindingError::CurrentNamespaceMismatch);
        }
        return Ok(lease.journal_identity());
    }

    let mut digest = Sha256::new();
    digest.update(ANDROID_RECOVERY_JOURNAL_IDENTITY_DOMAIN);
    digest.update(current_boot_identity.as_str().as_bytes());
    digest.update(current_network_namespace.device().to_be_bytes());
    digest.update(current_network_namespace.inode().to_be_bytes());
    digest.update(tool_digest);
    digest.update(durable_root.as_os_str().as_bytes());
    OwnershipJournalIdentity::new(digest.finalize().into())
        .map_err(|_| NativeXtablesAndroidRecoveryBindingError::ZeroIdentity)
}

#[derive(Debug)]
enum NativeXtablesAndroidRecoveryBindingError {
    Durable(NativeXtablesDurableError),
    MissingTargetMaterial,
    CurrentNamespaceMismatch,
    ZeroIdentity,
}

impl fmt::Display for NativeXtablesAndroidRecoveryBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Durable(source) => source.fmt(formatter),
            Self::MissingTargetMaterial => formatter.write_str(
                "native ownership artifacts exist without exact archived target material",
            ),
            Self::CurrentNamespaceMismatch => formatter.write_str(
                "current-boot native recovery state belongs to another network namespace",
            ),
            Self::ZeroIdentity => {
                formatter.write_str("derived native recovery owner identity is zero")
            }
        }
    }
}

impl Error for NativeXtablesAndroidRecoveryBindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Durable(source) => Some(source),
            Self::MissingTargetMaterial | Self::CurrentNamespaceMismatch | Self::ZeroIdentity => {
                None
            }
        }
    }
}

#[derive(Debug)]
pub struct NativeXtablesAndroidRuntimeError {
    operation: &'static str,
    source: Box<dyn Error + Send + Sync>,
}

impl NativeXtablesAndroidRuntimeError {
    fn new(operation: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            operation,
            source: Box::new(source),
        }
    }
}

impl fmt::Display for NativeXtablesAndroidRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.operation, self.source)
    }
}

impl Error for NativeXtablesAndroidRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Opaque platform admission bound to the exact discovered xtables tool identity.
///
/// There is no public constructor. Platform composition creates this value together with the
/// process converger, so callers cannot assert an arbitrary tool digest. Android planning evidence
/// remains one-shot and is consumed even when admission is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeXtablesCaptureAdmission {
    tool_digest: [u8; 32],
    binding: NativeXtablesAndroidRuntimeBinding,
}

impl NativeXtablesCaptureAdmission {
    fn new(tool_digest: [u8; 32], binding: NativeXtablesAndroidRuntimeBinding) -> Self {
        Self {
            tool_digest,
            binding,
        }
    }

    pub fn admit_android(
        &self,
        authority: AndroidMarkPlanningAuthority,
        placement: RpdbPlacementLease,
        artifacts: XtablesCaptureArtifactSet,
    ) -> Result<NativeXtablesCaptureTarget, NativeXtablesCaptureAdmissionError> {
        let routing_audit = android_routing_audit(&authority, placement)?;
        self.binding.ensure_current(&authority, routing_audit)?;
        let routing = *routing_audit.identities();
        let active_routing = [
            artifacts
                .pair(XtablesRestoreFamily::Ipv4)
                .is_some_and(|pair| pair.local_output().is_some())
                .then_some(routing[0]),
            artifacts
                .pair(XtablesRestoreFamily::Ipv6)
                .is_some_and(|pair| pair.local_output().is_some())
                .then_some(routing[1]),
        ]
        .into_iter()
        .flatten();
        let admitted = NativeXtablesAdmittedTarget::admit(
            artifacts,
            active_routing,
            routing_audit,
            self.tool_digest,
        )
        .map_err(|source| NativeXtablesCaptureAdmissionError::Target(source.to_string().into()))?;
        Ok(NativeXtablesCaptureTarget::from_admitted(admitted))
    }
}

fn local_output_loopback_index(
    authority: &AndroidMarkPlanningAuthority,
    family: NetworkAddressFamily,
) -> Result<InterfaceIndex, NativeXtablesCaptureAdmissionError> {
    let mut found = None;
    for entry in authority.topology_scope().entries() {
        if entry.domain() != AndroidTproxyTrafficDomainRequest::residual_local_output(family) {
            continue;
        }
        let observed = entry.report().input_interface_index();
        if found.is_some_and(|prior| prior != observed) {
            return Err(NativeXtablesCaptureAdmissionError::LoopbackIdentityMismatch);
        }
        found = Some(observed);
    }
    found.ok_or(NativeXtablesCaptureAdmissionError::MissingLocalOutputEvidence { family })
}

fn admitted_routing_identity(
    family: NetworkAddressFamily,
    placement: RpdbPlacementLease,
    mark: FwmarkCandidate,
    loopback_index: InterfaceIndex,
) -> Result<ManagedPolicyRoutingIdentity, NativeXtablesCaptureAdmissionError> {
    let placement = placement
        .family(family)
        .ok_or(NativeXtablesCaptureAdmissionError::MissingPlacementFamily { family })?;
    Ok(ManagedPolicyRoutingIdentity::bind_planned_android_target(
        family,
        placement,
        mark,
        loopback_index,
        NonZeroU32::new(NATIVE_ROUTE_METRIC).expect("native route metric is nonzero"),
        RouteProtocol::from_raw(NATIVE_ROUTE_PROTOCOL),
        RuleProtocol::from_raw(NATIVE_RULE_PROTOCOL),
    ))
}

fn android_routing_audit(
    authority: &AndroidMarkPlanningAuthority,
    placement: RpdbPlacementLease,
) -> Result<NativePolicyRoutingAudit, NativeXtablesCaptureAdmissionError> {
    let topology = authority.topology_scope();
    if placement.snapshot_id() != topology.snapshot_id() {
        return Err(NativeXtablesCaptureAdmissionError::PlacementSnapshotMismatch);
    }
    if placement.epoch() != topology.epoch() {
        return Err(NativeXtablesCaptureAdmissionError::PlacementEpochMismatch);
    }
    if placement.classifier_revision() != topology.classifier_revision() {
        return Err(NativeXtablesCaptureAdmissionError::PlacementClassifierMismatch);
    }

    let loopback = [
        local_output_loopback_index(authority, NetworkAddressFamily::Ipv4)?,
        local_output_loopback_index(authority, NetworkAddressFamily::Ipv6)?,
    ];
    if loopback[0] != loopback[1] {
        return Err(NativeXtablesCaptureAdmissionError::LoopbackIdentityMismatch);
    }
    let routing = [
        admitted_routing_identity(
            NetworkAddressFamily::Ipv4,
            placement,
            authority.candidate(),
            loopback[0],
        )?,
        admitted_routing_identity(
            NetworkAddressFamily::Ipv6,
            placement,
            authority.candidate(),
            loopback[1],
        )?,
    ];
    NativePolicyRoutingAudit::new(routing)
        .map_err(|_| NativeXtablesCaptureAdmissionError::LoopbackIdentityMismatch)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeXtablesAndroidRuntimeBinding {
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    journal_identity: OwnershipJournalIdentity,
    candidate: FwmarkCandidate,
    policy_identity: AndroidMarkDevicePolicyIdentity,
    policy_revision: AndroidMarkDevicePolicyRevision,
    routing_audit: NativePolicyRoutingAudit,
}

impl NativeXtablesAndroidRuntimeBinding {
    fn new(
        authority: &AndroidMarkPlanningAuthority,
        routing_audit: NativePolicyRoutingAudit,
    ) -> Self {
        Self {
            boot_identity: authority.boot_identity().clone(),
            network_namespace: authority.network_namespace(),
            journal_identity: authority.ownership_journal_identity(),
            candidate: authority.candidate(),
            policy_identity: authority.policy_identity().clone(),
            policy_revision: authority.policy_revision(),
            routing_audit,
        }
    }

    fn ensure_current(
        &self,
        authority: &AndroidMarkPlanningAuthority,
        routing_audit: NativePolicyRoutingAudit,
    ) -> Result<(), NativeXtablesCaptureAdmissionError> {
        let mismatch = if authority.boot_identity() != &self.boot_identity {
            Some("boot identity")
        } else if authority.network_namespace() != self.network_namespace {
            Some("network namespace")
        } else if authority.ownership_journal_identity() != self.journal_identity {
            Some("ownership journal")
        } else if authority.candidate() != self.candidate {
            Some("fwmark candidate")
        } else if authority.policy_identity() != &self.policy_identity
            || authority.policy_revision() != self.policy_revision
        {
            Some("device policy")
        } else if routing_audit != self.routing_audit {
            Some("policy routing")
        } else {
            None
        };
        mismatch.map_or(Ok(()), |field| {
            Err(NativeXtablesCaptureAdmissionError::RuntimeBindingMismatch(
                field,
            ))
        })
    }
}

#[derive(Debug)]
pub enum NativeXtablesCaptureAdmissionError {
    PlacementSnapshotMismatch,
    PlacementEpochMismatch,
    PlacementClassifierMismatch,
    MissingLocalOutputEvidence { family: NetworkAddressFamily },
    LoopbackIdentityMismatch,
    MissingPlacementFamily { family: NetworkAddressFamily },
    RuntimeBindingMismatch(&'static str),
    Target(Box<str>),
}

impl fmt::Display for NativeXtablesCaptureAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlacementSnapshotMismatch => formatter
                .write_str("RPDB placement snapshot differs from Android planning evidence"),
            Self::PlacementEpochMismatch => formatter
                .write_str("RPDB placement epoch differs from Android planning evidence"),
            Self::PlacementClassifierMismatch => formatter.write_str(
                "RPDB placement classifier revision differs from Android planning evidence",
            ),
            Self::MissingLocalOutputEvidence { family } => write!(
                formatter,
                "Android planning evidence has no residual local-OUTPUT anchor for {family:?}"
            ),
            Self::LoopbackIdentityMismatch => formatter.write_str(
                "Android planning evidence does not identify one exact dual-stack loopback interface",
            ),
            Self::MissingPlacementFamily { family } => write!(
                formatter,
                "RPDB placement has no complete {family:?} routing identity"
            ),
            Self::RuntimeBindingMismatch(field) => write!(
                formatter,
                "Android planning evidence differs from the native runtime {field} binding"
            ),
            Self::Target(detail) => write!(formatter, "native target admission rejected: {detail}"),
        }
    }
}

impl Error for NativeXtablesCaptureAdmissionError {}

/// Sealed mutation authority for the privileged Linux composition checkpoint.
///
/// The only constructor observes the current process and requires UID 0 in isolated user and
/// network namespaces. This type is available only under the explicit test feature and never
/// constructs or stands in for Android planning authority.
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
#[derive(Debug)]
pub struct NativeLinuxCompositionTestAuthority {
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    loopback_index: InterfaceIndex,
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
impl NativeLinuxCompositionTestAuthority {
    pub fn acquire() -> Result<Self, NativeLinuxCompositionTestError> {
        // SAFETY: `geteuid` has no arguments, does not dereference pointers, and cannot fail.
        let effective_uid = unsafe { libc::geteuid() };
        if effective_uid != 0 {
            return Err(NativeLinuxCompositionTestError::NotRoot { effective_uid });
        }

        let (network_handle, network_namespace) = observed_namespace("/proc/self/ns/net")?;
        let (_user_handle, user_namespace) = observed_namespace("/proc/self/ns/user")?;
        if !observed_uid_map_is_isolated()? {
            return Err(NativeLinuxCompositionTestError::NamespaceNotIsolated {
                namespace: "user",
            });
        }

        let network_owner = namespace_ioctl(&network_handle, NS_GET_USERNS).map_err(|source| {
            NativeLinuxCompositionTestError::Io {
                operation: "resolve network namespace owner",
                path: PathBuf::from("/proc/self/ns/net"),
                source,
            }
        })?;
        let network_owner_namespace =
            observed_namespace_handle(&network_owner, Path::new("/proc/self/ns/net(owner-user)"))?;
        if network_owner_namespace != user_namespace {
            return Err(NativeLinuxCompositionTestError::NamespaceNotIsolated {
                namespace: "network",
            });
        }

        let boot_path = Path::new("/proc/sys/kernel/random/boot_id");
        let boot_text = std::fs::read_to_string(boot_path).map_err(|source| {
            NativeLinuxCompositionTestError::Io {
                operation: "read boot identity",
                path: boot_path.to_owned(),
                source,
            }
        })?;
        let boot_identity = BootIdentity::parse(&boot_text).map_err(|source| {
            NativeLinuxCompositionTestError::Invalid(
                format!("cannot parse current boot identity: {source}").into_boxed_str(),
            )
        })?;

        let loopback = CString::new("lo").expect("canonical loopback name contains no NUL");
        // SAFETY: `loopback` is a readable NUL-terminated interface name for this call.
        let raw_index = unsafe { libc::if_nametoindex(loopback.as_ptr()) };
        let loopback_index = InterfaceIndex::new(raw_index).ok_or_else(|| {
            NativeLinuxCompositionTestError::Invalid(
                format!(
                    "isolated namespace has no loopback interface: {}",
                    std::io::Error::last_os_error()
                )
                .into_boxed_str(),
            )
        })?;
        let mut resolved = [0 as libc::c_char; libc::IF_NAMESIZE];
        // SAFETY: `resolved` is writable for IF_NAMESIZE bytes and `loopback_index` is nonzero.
        let resolved_ptr = unsafe { libc::if_indextoname(raw_index, resolved.as_mut_ptr()) };
        if resolved_ptr.is_null() {
            return Err(NativeLinuxCompositionTestError::Invalid(
                format!(
                    "cannot reverse-resolve isolated loopback interface: {}",
                    std::io::Error::last_os_error()
                )
                .into_boxed_str(),
            ));
        }
        // SAFETY: successful `if_indextoname` writes one NUL-terminated name into `resolved`.
        if unsafe { CStr::from_ptr(resolved_ptr) }.to_bytes() != b"lo" {
            return Err(NativeLinuxCompositionTestError::Invalid(
                "isolated loopback index does not resolve back to 'lo'".into(),
            ));
        }

        Ok(Self {
            boot_identity,
            network_namespace,
            loopback_index,
        })
    }

    #[must_use]
    pub const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    #[must_use]
    pub const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    pub fn compose(
        self,
        config: NativeLinuxCompositionTestConfig,
        routing: XtablesLocalOutputRoutingSpec,
        mark: FwmarkCandidate,
    ) -> Result<NativeLinuxCompositionTestRuntime, NativeLinuxCompositionTestError> {
        if !config.tool_root.is_absolute() || !config.durable_root.is_absolute() {
            return Err(NativeLinuxCompositionTestError::Invalid(
                "native composition tool and durable roots must be absolute".into(),
            ));
        }

        let ipv4 = routing.routing_for(NetworkAddressFamily::Ipv4).ok_or(
            NativeLinuxCompositionTestError::MissingRoutingFamily {
                family: NetworkAddressFamily::Ipv4,
            },
        )?;
        let ipv6 = routing.routing_for(NetworkAddressFamily::Ipv6).ok_or(
            NativeLinuxCompositionTestError::MissingRoutingFamily {
                family: NetworkAddressFamily::Ipv6,
            },
        )?;
        let routing_audit = NativePolicyRoutingAudit::new([
            ManagedPolicyRoutingIdentity::bind_linux_composition_test_target(
                NetworkAddressFamily::Ipv4,
                ipv4,
                mark,
                self.loopback_index,
            ),
            ManagedPolicyRoutingIdentity::bind_linux_composition_test_target(
                NetworkAddressFamily::Ipv6,
                ipv6,
                mark,
                self.loopback_index,
            ),
        ])
        .map_err(|source| NativeLinuxCompositionTestError::Invalid(source.to_string().into()))?;

        let process = XtablesRestoreProcessConfig::new(config.wait_seconds, config.timeout)
            .map_err(|source| {
                NativeLinuxCompositionTestError::Process(source.to_string().into())
            })?;
        let tools =
            XtablesToolSetProcessAdapter::discover_standard(&config.tool_root, true, process)
                .map_err(|source| {
                    NativeLinuxCompositionTestError::Process(source.to_string().into())
                })?;
        let tool_digest = *tools.identity().digest().as_bytes();
        let journal_identity = linux_test_journal_identity(
            &self.boot_identity,
            self.network_namespace,
            &config.durable_root,
            tool_digest,
        )?;
        let admission = NativeLinuxCompositionTestAdmission {
            network_namespace: self.network_namespace,
            loopback_index: self.loopback_index,
            routing_audit,
            tool_digest,
        };
        let environment = NativeXtablesEnvironment::new(
            self.boot_identity,
            self.network_namespace,
            journal_identity,
            routing_audit,
        );
        let writer = NativeXtablesRuntimeWriter::new(
            NativeXtablesProcessOwnerAdapter::new(tools),
            NativeXtablesDurableStore::new(config.durable_root),
            environment,
        )
        .map_err(|source| NativeLinuxCompositionTestError::Runtime(source.to_string().into()))?;
        Ok(NativeLinuxCompositionTestRuntime {
            admission,
            convergence: NativeXtablesCaptureConverger::from_runtime_writer(writer),
        })
    }
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
fn observed_namespace(
    path: &'static str,
) -> Result<(File, NetworkNamespaceIdentity), NativeLinuxCompositionTestError> {
    let path = Path::new(path);
    let handle = File::open(path).map_err(|source| NativeLinuxCompositionTestError::Io {
        operation: "open namespace identity",
        path: path.to_owned(),
        source,
    })?;
    let identity = observed_namespace_handle(&handle, path)?;
    Ok((handle, identity))
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
fn observed_namespace_handle(
    handle: &File,
    path: &Path,
) -> Result<NetworkNamespaceIdentity, NativeLinuxCompositionTestError> {
    let metadata = handle
        .metadata()
        .map_err(|source| NativeLinuxCompositionTestError::Io {
            operation: "inspect namespace identity",
            path: path.to_owned(),
            source,
        })?;
    NetworkNamespaceIdentity::new(metadata.dev(), metadata.ino()).ok_or_else(|| {
        NativeLinuxCompositionTestError::Invalid(
            format!("namespace {} has a zero inode", path.display()).into_boxed_str(),
        )
    })
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
fn namespace_ioctl(handle: &File, request: libc::c_ulong) -> Result<File, std::io::Error> {
    // SAFETY: `handle` is a pinned namespace descriptor and both requests return a new descriptor
    // without reading a variadic argument. A nonnegative result is uniquely owned by this call.
    let descriptor = unsafe { libc::ioctl(handle.as_raw_fd(), request) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful namespace ioctls return a new descriptor owned by the caller.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
fn observed_uid_map_is_isolated() -> Result<bool, NativeLinuxCompositionTestError> {
    const INITIAL_UID_MAP: (u64, u64, u64) = (0, 0, u32::MAX as u64);
    const MAX_UID_MAP_BYTES: usize = 4 * 1024;

    let path = Path::new("/proc/self/uid_map");
    let text =
        std::fs::read_to_string(path).map_err(|source| NativeLinuxCompositionTestError::Io {
            operation: "read current user namespace UID map",
            path: path.to_owned(),
            source,
        })?;
    if text.len() > MAX_UID_MAP_BYTES {
        return Err(NativeLinuxCompositionTestError::Invalid(
            "current user namespace UID map exceeds 4 KiB".into(),
        ));
    }

    let mut mappings = Vec::new();
    for line in text.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(NativeLinuxCompositionTestError::Invalid(
                "current user namespace UID map has an invalid field count".into(),
            ));
        }
        let mut parsed = [0_u64; 3];
        for (target, field) in parsed.iter_mut().zip(fields) {
            *target = field.parse::<u64>().map_err(|_| {
                NativeLinuxCompositionTestError::Invalid(
                    "current user namespace UID map contains a non-decimal field".into(),
                )
            })?;
        }
        let [inside, outside, length] = parsed;
        let id_domain_end = u64::from(u32::MAX) + 1;
        if length == 0
            || inside
                .checked_add(length)
                .is_none_or(|end| end > id_domain_end)
            || outside
                .checked_add(length)
                .is_none_or(|end| end > id_domain_end)
        {
            return Err(NativeLinuxCompositionTestError::Invalid(
                "current user namespace UID map contains an invalid range".into(),
            ));
        }
        mappings.push((inside, outside, length));
    }
    if mappings.is_empty() || !mappings.iter().any(|&(inside, _, _)| inside == 0) {
        return Ok(false);
    }
    Ok(mappings.as_slice() != [INITIAL_UID_MAP])
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
fn linux_test_journal_identity(
    boot_identity: &BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    durable_root: &Path,
    tool_digest: [u8; 32],
) -> Result<OwnershipJournalIdentity, NativeLinuxCompositionTestError> {
    let mut digest = Sha256::new();
    digest.update(b"Flux privileged Linux native composition journal\0sha256-v1\0");
    digest.update(boot_identity.as_str().as_bytes());
    digest.update(network_namespace.device().to_be_bytes());
    digest.update(network_namespace.inode().to_be_bytes());
    digest.update(durable_root.as_os_str().as_bytes());
    digest.update(tool_digest);
    OwnershipJournalIdentity::new(digest.finalize().into()).map_err(|source| {
        NativeLinuxCompositionTestError::Invalid(source.to_string().into_boxed_str())
    })
}

/// Process and durable-store configuration for the Linux-only native composition checkpoint.
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLinuxCompositionTestConfig {
    tool_root: PathBuf,
    durable_root: PathBuf,
    wait_seconds: u16,
    timeout: Duration,
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
impl NativeLinuxCompositionTestConfig {
    #[must_use]
    pub fn new(
        tool_root: impl AsRef<Path>,
        durable_root: impl AsRef<Path>,
        wait_seconds: u16,
        timeout: Duration,
    ) -> Self {
        Self {
            tool_root: tool_root.as_ref().to_owned(),
            durable_root: durable_root.as_ref().to_owned(),
            wait_seconds,
            timeout,
        }
    }
}

/// Opaque host-test admission tied to one isolated namespace, routing audit, and tool digest.
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
pub struct NativeLinuxCompositionTestAdmission {
    network_namespace: NetworkNamespaceIdentity,
    loopback_index: InterfaceIndex,
    routing_audit: NativePolicyRoutingAudit,
    tool_digest: [u8; 32],
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
impl NativeLinuxCompositionTestAdmission {
    pub fn admit_linux_test(
        &self,
        network_namespace: NetworkNamespaceIdentity,
        artifacts: XtablesCaptureArtifactSet,
    ) -> Result<NativeXtablesCaptureTarget, NativeLinuxCompositionTestError> {
        if network_namespace != self.network_namespace {
            return Err(NativeLinuxCompositionTestError::NamespaceBindingMismatch);
        }

        let mut routing = Vec::with_capacity(2);
        for (family, restore_family) in [
            (NetworkAddressFamily::Ipv4, XtablesRestoreFamily::Ipv4),
            (NetworkAddressFamily::Ipv6, XtablesRestoreFamily::Ipv6),
        ] {
            let requirements = artifacts
                .pair(restore_family)
                .and_then(|pair| pair.local_output())
                .ok_or(NativeLinuxCompositionTestError::MissingRoutingFamily { family })?;
            let identity =
                ManagedPolicyRoutingIdentity::bind(requirements.routing(), self.loopback_index)
                    .map_err(|source| {
                        NativeLinuxCompositionTestError::Admission(source.to_string().into())
                    })?;
            if identity != self.routing_audit.identity(family) {
                return Err(NativeLinuxCompositionTestError::RoutingBindingMismatch { family });
            }
            routing.push(identity);
        }
        let admitted = NativeXtablesAdmittedTarget::admit(
            artifacts,
            routing,
            self.routing_audit,
            self.tool_digest,
        )
        .map_err(|source| NativeLinuxCompositionTestError::Admission(source.to_string().into()))?;
        Ok(NativeXtablesCaptureTarget::from_admitted(admitted))
    }
}

/// Platform half of the single-owner privileged native composition checkpoint.
#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
pub struct NativeLinuxCompositionTestRuntime {
    admission: NativeLinuxCompositionTestAdmission,
    convergence: NativeXtablesCaptureConverger,
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
impl NativeLinuxCompositionTestRuntime {
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        NativeLinuxCompositionTestAdmission,
        NativeXtablesCaptureConverger,
    ) {
        (self.admission, self.convergence)
    }
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
#[derive(Debug)]
pub enum NativeLinuxCompositionTestError {
    NotRoot {
        effective_uid: libc::uid_t,
    },
    NamespaceNotIsolated {
        namespace: &'static str,
    },
    NamespaceBindingMismatch,
    MissingRoutingFamily {
        family: NetworkAddressFamily,
    },
    RoutingBindingMismatch {
        family: NetworkAddressFamily,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Invalid(Box<str>),
    Process(Box<str>),
    Runtime(Box<str>),
    Admission(Box<str>),
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
impl fmt::Display for NativeLinuxCompositionTestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRoot { effective_uid } => write!(
                formatter,
                "native composition test requires isolated effective UID 0, found {effective_uid}"
            ),
            Self::NamespaceNotIsolated { namespace } => write!(
                formatter,
                "native composition test requires an isolated {namespace} namespace"
            ),
            Self::NamespaceBindingMismatch => formatter.write_str(
                "host Generation namespace differs from the sealed Linux test namespace",
            ),
            Self::MissingRoutingFamily { family } => write!(
                formatter,
                "native composition test requires local-OUTPUT routing for {family:?}"
            ),
            Self::RoutingBindingMismatch { family } => write!(
                formatter,
                "admitted {family:?} artifacts differ from the sealed routing audit"
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::Invalid(detail) => formatter.write_str(detail),
            Self::Process(detail) => write!(formatter, "xtables process composition: {detail}"),
            Self::Runtime(detail) => write!(formatter, "native runtime composition: {detail}"),
            Self::Admission(detail) => write!(formatter, "native test target admission: {detail}"),
        }
    }
}

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
impl Error for NativeLinuxCompositionTestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) struct NativeXtablesRuntimeWriter<A>
where
    A: NativeXtablesOwnerAdapter,
{
    owner: NativeXtablesOwner<A, DurableNativeXtablesTargetResolver>,
    resolver: DurableNativeXtablesTargetResolver,
    recovered: bool,
}

/// Opaque native target admitted inside `flux-platform`.
///
/// No public constructor exists. Host inspection and test evidence therefore cannot manufacture a
/// value accepted by the production process converger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeXtablesCaptureTarget {
    inner: NativeXtablesAdmittedTarget,
    identity: NativeCaptureTargetIdentity,
}

impl NativeXtablesCaptureTarget {
    pub(crate) fn from_admitted(inner: NativeXtablesAdmittedTarget) -> Self {
        let identity = public_identity(inner.identity());
        Self { inner, identity }
    }

    #[must_use]
    pub const fn identity(&self) -> NativeCaptureTargetIdentity {
        self.identity
    }
}

/// Opaque production process converger. Construction remains platform-private.
pub struct NativeXtablesCaptureConverger {
    inner: NativeXtablesRuntimeWriter<NativeXtablesProcessOwnerAdapter>,
}

impl NativeXtablesCaptureConverger {
    #[allow(
        dead_code,
        reason = "C2 will construct the qualified production converger"
    )]
    pub(crate) const fn from_runtime_writer(
        inner: NativeXtablesRuntimeWriter<NativeXtablesProcessOwnerAdapter>,
    ) -> Self {
        Self { inner }
    }
}

#[derive(Debug)]
pub struct NativeXtablesCaptureConvergenceError {
    source: NativeXtablesRuntimeWriterError,
}

impl fmt::Display for NativeXtablesCaptureConvergenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for NativeXtablesCaptureConvergenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl NativeCaptureConvergence for NativeXtablesCaptureConverger {
    type Target = NativeXtablesCaptureTarget;
    type Identity = NativeCaptureTargetIdentity;
    type Error = NativeXtablesCaptureConvergenceError;

    fn target_identity(target: &Self::Target) -> Self::Identity {
        target.identity
    }

    fn recover(&mut self) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error> {
        self.inner
            .recover()
            .map(public_report)
            .map_err(|source| NativeXtablesCaptureConvergenceError { source })
    }

    fn converge(
        &mut self,
        desired: NativeCaptureDesired<Self::Target>,
    ) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error> {
        let desired = match desired {
            NativeCaptureDesired::Active(target) => {
                NativeXtablesDesiredTarget::Active(target.inner)
            }
            NativeCaptureDesired::Stopped => NativeXtablesDesiredTarget::Stopped,
        };
        self.inner
            .converge(desired)
            .map(public_report)
            .map_err(|source| NativeXtablesCaptureConvergenceError { source })
    }
}

fn public_report(
    report: NativeXtablesConvergenceReport,
) -> NativeCaptureConvergenceReport<NativeCaptureTargetIdentity> {
    let state = match report.state() {
        NativeXtablesConvergedState::Active(identity) => {
            NativeCaptureConvergedState::Active(public_identity(identity))
        }
        NativeXtablesConvergedState::CleanAbsent => NativeCaptureConvergedState::CleanAbsent,
    };
    NativeCaptureConvergenceReport::new(state, report.changed())
}

fn public_identity(identity: NativeXtablesTargetIdentity) -> NativeCaptureTargetIdentity {
    NativeCaptureTargetIdentity::new(
        identity.generation(),
        identity.target_digest(),
        identity.tool_digest(),
        identity.routing_digest(),
    )
}

impl<A> NativeXtablesRuntimeWriter<A>
where
    A: NativeXtablesOwnerAdapter,
{
    pub(crate) fn new(
        adapter: A,
        durable: NativeXtablesDurableStore,
        environment: NativeXtablesEnvironment,
    ) -> Result<Self, NativeXtablesRuntimeWriterError> {
        let resolver = DurableNativeXtablesTargetResolver::open(durable.clone())
            .map_err(|source| NativeXtablesRuntimeWriterError::TargetArchive(Box::new(source)))?;
        let owner = NativeXtablesOwner::new(adapter, resolver.clone(), durable, environment);
        Ok(Self {
            owner,
            resolver,
            recovered: false,
        })
    }

    pub(crate) fn recover(
        &mut self,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesRuntimeWriterError> {
        let _transaction = self.begin_transaction()?;
        let report = match self.owner.recover() {
            Ok(report) => report,
            Err(source) => {
                self.recovered = false;
                return Err(NativeXtablesRuntimeWriterError::Owner(Box::new(source)));
            }
        };
        if let Err(source) = self.settle_archive(report.state()) {
            self.recovered = false;
            return Err(source);
        }
        self.recovered = true;
        Ok(report)
    }

    pub(crate) fn converge(
        &mut self,
        target: NativeXtablesDesiredTarget,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesRuntimeWriterError> {
        if !self.recovered {
            return Err(NativeXtablesRuntimeWriterError::RecoveryRequired);
        }
        let _transaction = self.begin_transaction()?;
        if let NativeXtablesDesiredTarget::Active(target) = &target {
            self.resolver.stage(target.clone()).map_err(|source| {
                NativeXtablesRuntimeWriterError::TargetArchive(Box::new(source))
            })?;
        }
        let report = match self.owner.converge(target) {
            Ok(report) => report,
            Err(source) => {
                self.recovered = false;
                return Err(NativeXtablesRuntimeWriterError::Owner(Box::new(source)));
            }
        };
        if let Err(source) = self.settle_archive(report.state()) {
            self.recovered = false;
            return Err(source);
        }
        Ok(report)
    }

    fn begin_transaction(
        &mut self,
    ) -> Result<NativeXtablesRuntimeGuard, NativeXtablesRuntimeWriterError> {
        let guard = match self.owner.durable.acquire_runtime_guard() {
            Ok(guard) => guard,
            Err(source) => {
                self.recovered = false;
                return Err(NativeXtablesRuntimeWriterError::Durable(Box::new(source)));
            }
        };
        if let Err(source) = self.resolver.refresh() {
            self.recovered = false;
            return Err(NativeXtablesRuntimeWriterError::TargetArchive(Box::new(
                source,
            )));
        }
        Ok(guard)
    }

    fn settle_archive(
        &self,
        state: NativeXtablesConvergedState,
    ) -> Result<(), NativeXtablesRuntimeWriterError> {
        if matches!(state, NativeXtablesConvergedState::CleanAbsent)
            && self
                .owner
                .durable
                .load_journal()
                .map_err(|source| NativeXtablesRuntimeWriterError::SettledDurable {
                    state,
                    source: Box::new(source),
                })?
                .is_some()
        {
            return Ok(());
        }
        self.resolver.retain_state(state).map_err(|source| {
            NativeXtablesRuntimeWriterError::SettledArchive {
                state,
                source: Box::new(source),
            }
        })
    }

    pub(crate) fn observe(
        &mut self,
        desired: NativeXtablesDryRunTarget<'_>,
    ) -> Result<NativeXtablesDryRunReport, NativeXtablesRuntimeWriterError> {
        self.resolver
            .refresh()
            .map_err(|source| NativeXtablesRuntimeWriterError::TargetArchive(Box::new(source)))?;
        let archived_targets = self
            .resolver
            .identities()
            .map_err(|source| NativeXtablesRuntimeWriterError::TargetArchive(Box::new(source)))?
            .into_boxed_slice();
        let journal_present = self
            .owner
            .durable
            .load_journal()
            .map_err(|source| NativeXtablesRuntimeWriterError::Durable(Box::new(source)))?
            .is_some();
        let desired_identity = match desired {
            NativeXtablesDryRunTarget::Active(target) => Some(target.identity()),
            NativeXtablesDryRunTarget::Stopped => None,
        };
        let tool_identity_matches = desired_identity
            .is_none_or(|identity| self.owner.adapter.tool_digest() == identity.tool_digest());

        let exact_desired = match desired {
            NativeXtablesDryRunTarget::Active(target) if tool_identity_matches => self
                .owner
                .target_is_exact_active(target)
                .map_err(|source| NativeXtablesRuntimeWriterError::Owner(Box::new(source)))?,
            NativeXtablesDryRunTarget::Active(_) => false,
            NativeXtablesDryRunTarget::Stopped => false,
        };
        let clean_absent = if exact_desired {
            false
        } else {
            match self
                .owner
                .require_global_xtables_absence()
                .and_then(|()| self.owner.require_recovery_policy_absence())
            {
                Ok(()) => true,
                Err(NativeXtablesOwnerError::LiveStateConflict(_)) => false,
                Err(source) => {
                    return Err(NativeXtablesRuntimeWriterError::Owner(Box::new(source)));
                }
            }
        };
        let disposition = match (desired, exact_desired, clean_absent, tool_identity_matches) {
            (NativeXtablesDryRunTarget::Active(_), true, _, true)
            | (NativeXtablesDryRunTarget::Stopped, _, true, _) => {
                NativeXtablesDryRunDisposition::NoChange
            }
            (NativeXtablesDryRunTarget::Active(_), false, true, true) => {
                NativeXtablesDryRunDisposition::Activate
            }
            (NativeXtablesDryRunTarget::Stopped, _, false, _) => {
                NativeXtablesDryRunDisposition::RecoverOrStop
            }
            (NativeXtablesDryRunTarget::Active(_), _, _, false)
            | (NativeXtablesDryRunTarget::Active(_), false, false, true) => {
                NativeXtablesDryRunDisposition::Blocked
            }
        };
        Ok(NativeXtablesDryRunReport {
            recovered: self.recovered,
            journal_present,
            archived_targets,
            desired_identity,
            tool_identity_matches,
            exact_desired,
            clean_absent,
            disposition,
        })
    }

    #[cfg(test)]
    pub(crate) fn into_parts(self) -> (A, NativeXtablesDurableStore, NativeXtablesEnvironment) {
        let environment = self.owner.environment.clone();
        let (adapter, _resolver, durable) = self.owner.into_parts();
        (adapter, durable, environment)
    }

    #[cfg(test)]
    pub(crate) const fn test_adapter(&self) -> &A {
        &self.owner.adapter
    }

    #[cfg(test)]
    pub(crate) const fn test_adapter_mut(&mut self) -> &mut A {
        &mut self.owner.adapter
    }

    #[cfg(test)]
    pub(crate) fn test_archived_identities(
        &self,
    ) -> Result<Vec<NativeXtablesTargetIdentity>, NativeXtablesTargetArchiveError> {
        self.resolver.identities()
    }
}

impl NativeXtablesRuntimeWriter<NativeXtablesProcessOwnerAdapter> {
    pub(crate) fn open_process(
        config: NativeXtablesProcessWriterConfig,
        environment: NativeXtablesEnvironment,
    ) -> Result<Self, NativeXtablesRuntimeWriterError> {
        let process = XtablesRestoreProcessConfig::new(config.wait_seconds, config.timeout)
            .map_err(|source| NativeXtablesRuntimeWriterError::ProcessAdapter(Box::new(source)))?;
        let tools = XtablesToolSetProcessAdapter::discover_standard(
            &config.tool_root,
            config.require_ipv6,
            process,
        )
        .map_err(|source| NativeXtablesRuntimeWriterError::ProcessAdapter(Box::new(source)))?;
        Self::new(
            NativeXtablesProcessOwnerAdapter::new(tools),
            NativeXtablesDurableStore::new(config.durable_root),
            environment,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesProcessWriterConfig {
    tool_root: PathBuf,
    durable_root: PathBuf,
    require_ipv6: bool,
    wait_seconds: u16,
    timeout: Duration,
}

impl NativeXtablesProcessWriterConfig {
    #[must_use]
    pub(crate) fn new(
        tool_root: impl AsRef<Path>,
        durable_root: impl AsRef<Path>,
        require_ipv6: bool,
        wait_seconds: u16,
        timeout: Duration,
    ) -> Self {
        Self {
            tool_root: tool_root.as_ref().to_owned(),
            durable_root: durable_root.as_ref().to_owned(),
            require_ipv6,
            wait_seconds,
            timeout,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NativeXtablesDryRunTarget<'a> {
    Active(&'a NativeXtablesAdmittedTarget),
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeXtablesDryRunDisposition {
    NoChange,
    Activate,
    RecoverOrStop,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesDryRunReport {
    recovered: bool,
    journal_present: bool,
    archived_targets: Box<[NativeXtablesTargetIdentity]>,
    desired_identity: Option<NativeXtablesTargetIdentity>,
    tool_identity_matches: bool,
    exact_desired: bool,
    clean_absent: bool,
    disposition: NativeXtablesDryRunDisposition,
}

impl NativeXtablesDryRunReport {
    #[must_use]
    pub(crate) const fn recovered(&self) -> bool {
        self.recovered
    }

    #[must_use]
    pub(crate) const fn journal_present(&self) -> bool {
        self.journal_present
    }

    #[must_use]
    pub(crate) const fn archived_targets(&self) -> &[NativeXtablesTargetIdentity] {
        &self.archived_targets
    }

    #[must_use]
    pub(crate) const fn desired_identity(&self) -> Option<NativeXtablesTargetIdentity> {
        self.desired_identity
    }

    #[must_use]
    pub(crate) const fn tool_identity_matches(&self) -> bool {
        self.tool_identity_matches
    }

    #[must_use]
    pub(crate) const fn exact_desired(&self) -> bool {
        self.exact_desired
    }

    #[must_use]
    pub(crate) const fn clean_absent(&self) -> bool {
        self.clean_absent
    }

    #[must_use]
    pub(crate) const fn disposition(&self) -> NativeXtablesDryRunDisposition {
        self.disposition
    }
}

#[derive(Debug)]
pub(crate) enum NativeXtablesRuntimeWriterError {
    RecoveryRequired,
    TargetArchive(Box<NativeXtablesTargetArchiveError>),
    Durable(Box<NativeXtablesDurableError>),
    ProcessAdapter(Box<XtablesRestoreProcessError>),
    Owner(Box<NativeXtablesOwnerError>),
    SettledArchive {
        state: NativeXtablesConvergedState,
        source: Box<NativeXtablesTargetArchiveError>,
    },
    SettledDurable {
        state: NativeXtablesConvergedState,
        source: Box<NativeXtablesDurableError>,
    },
}

impl fmt::Display for NativeXtablesRuntimeWriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecoveryRequired => formatter
                .write_str("native runtime recovery must complete before convergence is allowed"),
            Self::TargetArchive(source) => source.fmt(formatter),
            Self::Durable(source) => source.fmt(formatter),
            Self::ProcessAdapter(source) => source.fmt(formatter),
            Self::Owner(source) => source.fmt(formatter),
            Self::SettledArchive { state, source } => write!(
                formatter,
                "native runtime settled at {state:?}, but target-archive maintenance failed: {source}"
            ),
            Self::SettledDurable { state, source } => write!(
                formatter,
                "native runtime settled at {state:?}, but terminal-journal inspection failed: {source}"
            ),
        }
    }
}

impl Error for NativeXtablesRuntimeWriterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TargetArchive(source) => Some(source.as_ref()),
            Self::Durable(source) => Some(source.as_ref()),
            Self::ProcessAdapter(source) => Some(source.as_ref()),
            Self::Owner(source) => Some(source.as_ref()),
            Self::SettledArchive { source, .. } => Some(source.as_ref()),
            Self::SettledDurable { source, .. } => Some(source.as_ref()),
            Self::RecoveryRequired => None,
        }
    }
}

#[cfg(test)]
mod admission_tests {
    use flux_core::{RpdbFamilyPlacement, RulePriority, RuleTableId};

    use super::*;

    #[test]
    fn canonical_routing_target_pins_platform_owned_identity_constants() {
        let placement = RpdbFamilyPlacement::with_address_bypass(
            RulePriority::from_raw(30_998),
            RulePriority::from_raw(30_999),
            RuleTableId::from_raw(20_253),
        )
        .expect("fixture placement");

        let routing = canonical_routing_target(placement);

        assert_eq!(routing.priority(), placement.proxy_priority());
        assert_eq!(routing.table().get(), placement.private_table().get());
        assert_eq!(routing.route_metric().get(), 1_024);
        assert_eq!(routing.route_protocol().raw(), 4);
        assert_eq!(routing.rule_protocol().raw(), 99);
    }
}
