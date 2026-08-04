use std::error::Error;
use std::fmt::Debug;
use std::num::{NonZeroU16, NonZeroU64};

use flux_core::{
    BootIdentity, GenerationId, NetworkNamespaceIdentity, OwnershipJournalIdentity,
    OwnershipJournalRevision,
};

/// Opaque identity of one exact native capture target.
///
/// The digests bind platform-private xtables, tool, and policy-routing material. They are
/// diagnostic identity only and do not grant mutation authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NativeCaptureTargetIdentity {
    generation: GenerationId,
    target_digest: [u8; 32],
    tool_digest: [u8; 32],
    routing_digest: [u8; 32],
}

impl NativeCaptureTargetIdentity {
    #[must_use]
    pub(crate) const fn new(
        generation: GenerationId,
        target_digest: [u8; 32],
        tool_digest: [u8; 32],
        routing_digest: [u8; 32],
    ) -> Self {
        Self {
            generation,
            target_digest,
            tool_digest,
            routing_digest,
        }
    }

    #[must_use]
    pub const fn generation(self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub const fn target_digest(self) -> [u8; 32] {
        self.target_digest
    }

    #[must_use]
    pub const fn tool_digest(self) -> [u8; 32] {
        self.tool_digest
    }

    #[must_use]
    pub const fn routing_digest(self) -> [u8; 32] {
        self.routing_digest
    }
}

/// Descriptor-anchored read-only evidence for one exact active native capture owner.
///
/// Construction remains platform-private. The value carries no writer, lease, target, or cleanup
/// authority and can only be observed through [`NativeCaptureConvergence`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCaptureOwnershipObservation {
    target: NativeCaptureTargetIdentity,
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    journal_identity: OwnershipJournalIdentity,
    journal_revision: OwnershipJournalRevision,
    record_schema_version: NonZeroU16,
    record_device: u64,
    record_inode: NonZeroU64,
    record_digest: [u8; 32],
}

impl NativeCaptureOwnershipObservation {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) const fn new(
        target: NativeCaptureTargetIdentity,
        boot_identity: BootIdentity,
        network_namespace: NetworkNamespaceIdentity,
        journal_identity: OwnershipJournalIdentity,
        journal_revision: OwnershipJournalRevision,
        record_schema_version: NonZeroU16,
        record_device: u64,
        record_inode: NonZeroU64,
        record_digest: [u8; 32],
    ) -> Self {
        Self {
            target,
            boot_identity,
            network_namespace,
            journal_identity,
            journal_revision,
            record_schema_version,
            record_device,
            record_inode,
            record_digest,
        }
    }

    #[must_use]
    pub const fn target(&self) -> NativeCaptureTargetIdentity {
        self.target
    }

    #[must_use]
    pub const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    #[must_use]
    pub const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub const fn journal_identity(&self) -> OwnershipJournalIdentity {
        self.journal_identity
    }

    #[must_use]
    pub const fn journal_revision(&self) -> OwnershipJournalRevision {
        self.journal_revision
    }

    #[must_use]
    pub const fn record_schema_version(&self) -> NonZeroU16 {
        self.record_schema_version
    }

    #[must_use]
    pub const fn record_device(&self) -> u64 {
        self.record_device
    }

    #[must_use]
    pub const fn record_inode(&self) -> NonZeroU64 {
        self.record_inode
    }

    #[must_use]
    pub const fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeCaptureDesired<T> {
    Active(T),
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCaptureConvergedState<I> {
    Active(I),
    CleanAbsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureConvergenceReport<I> {
    state: NativeCaptureConvergedState<I>,
    changed: bool,
}

impl<I> NativeCaptureConvergenceReport<I> {
    #[must_use]
    pub const fn new(state: NativeCaptureConvergedState<I>, changed: bool) -> Self {
        Self { state, changed }
    }

    #[must_use]
    pub const fn state(&self) -> &NativeCaptureConvergedState<I> {
        &self.state
    }

    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changed
    }
}

/// Coordinator-facing native capture interface.
///
/// Implementations own recovery, exact readback, mutation ordering, compensation, and durable
/// state. Callers can request only startup recovery or convergence to one opaque target/absence.
pub trait NativeCaptureConvergence: Send + 'static {
    type Target: Clone + Send + 'static;
    type Identity: Copy + Debug + Eq + Send + Sync + 'static;
    type Error: Error + Send + Sync + 'static;

    fn target_identity(target: &Self::Target) -> Self::Identity;

    fn recover(&mut self) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error>;

    /// Observes the exact active native ownership record without granting mutation authority.
    ///
    /// Non-native implementations remain unsupported by default. A missing observation must not
    /// be interpreted as positive evidence by a caller that requires a functional canary.
    fn observe_active_ownership(
        &mut self,
    ) -> Result<Option<NativeCaptureOwnershipObservation>, Self::Error> {
        Ok(None)
    }

    fn converge(
        &mut self,
        desired: NativeCaptureDesired<Self::Target>,
    ) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error>;
}
