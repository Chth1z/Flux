use sha2::{Digest, Sha256};

/// Length-framed encoder for stable, domain-separated evidence identities.
pub(crate) struct CanonicalEvidenceDigest {
    digest: Sha256,
}

impl CanonicalEvidenceDigest {
    pub(crate) fn new(domain: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(domain);
        Self { digest }
    }

    pub(crate) fn tag(&mut self, value: u8) {
        self.digest.update([value]);
    }

    pub(crate) fn boolean(&mut self, value: bool) {
        self.tag(u8::from(value));
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.digest.update(value.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.digest.update(value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.digest.update(value.to_be_bytes());
    }

    pub(crate) fn usize(&mut self, value: usize) {
        self.u64(u64::try_from(value).expect("bounded evidence length fits u64"));
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.usize(value.len());
        self.digest.update(value);
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.digest.finalize().into()
    }
}
