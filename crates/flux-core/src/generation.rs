use std::fmt;
use std::num::NonZeroU32;

/// Canonical identity of one immutable Desired State realization.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct GenerationId(NonZeroU32);

impl GenerationId {
    pub const INITIAL: Self = Self(NonZeroU32::MIN);

    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }
}

impl fmt::Display for GenerationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_identity_is_nonzero_and_advances_without_saturation() {
        assert_eq!(GenerationId::new(0), None);
        assert_eq!(GenerationId::INITIAL.get(), 1);
        assert_eq!(
            GenerationId::INITIAL.checked_next().map(GenerationId::get),
            Some(2)
        );
        assert_eq!(
            GenerationId::new(u32::MAX).and_then(GenerationId::checked_next),
            None
        );
    }
}
