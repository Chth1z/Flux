use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_PROCESS_AUTHORITY_OPENING_ID: AtomicU64 = AtomicU64::new(1);

/// Process-local correlation identity issued only while wrapping an opened,
/// child-origin process handle in non-cloneable authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ProcessAuthorityOpeningId(NonZeroU64);

impl ProcessAuthorityOpeningId {
    pub(crate) fn allocate() -> Result<Self, ProcessAuthorityOpeningIdExhausted> {
        let raw = NEXT_PROCESS_AUTHORITY_OPENING_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ProcessAuthorityOpeningIdExhausted)?;
        NonZeroU64::new(raw)
            .map(Self)
            .ok_or(ProcessAuthorityOpeningIdExhausted)
    }

    #[must_use]
    pub(crate) const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessAuthorityOpeningIdExhausted;

#[cfg(test)]
mod tests {
    use super::ProcessAuthorityOpeningId;

    #[test]
    fn process_authority_openings_are_nonzero_and_distinct() {
        let first = ProcessAuthorityOpeningId::allocate().expect("allocate first opening");
        let second = ProcessAuthorityOpeningId::allocate().expect("allocate second opening");

        assert_ne!(first, second);
        assert_ne!(first.get(), 0);
        assert_ne!(second.get(), 0);
    }
}
