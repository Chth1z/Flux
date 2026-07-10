//! Deterministic model adapters and fixtures for Flux tests.

use std::cell::Cell;

use flux_platform::{KernelReleaseSource, PlatformError};

#[derive(Debug)]
pub struct StaticKernelReleaseSource {
    release: String,
    calls: Cell<usize>,
}

impl StaticKernelReleaseSource {
    #[must_use]
    pub fn new(release: impl Into<String>) -> Self {
        Self {
            release: release.into(),
            calls: Cell::new(0),
        }
    }

    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl KernelReleaseSource for StaticKernelReleaseSource {
    fn kernel_release(&self) -> Result<String, PlatformError> {
        self.calls.set(self.calls.get().saturating_add(1));
        Ok(self.release.clone())
    }
}
