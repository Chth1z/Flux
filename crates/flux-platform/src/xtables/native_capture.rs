use std::error::Error;
use std::fmt::Debug;

use flux_core::GenerationId;

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

    fn converge(
        &mut self,
        desired: NativeCaptureDesired<Self::Target>,
    ) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error>;
}
