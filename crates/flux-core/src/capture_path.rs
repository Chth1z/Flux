/// Stable product identity of the mechanism that realizes one Capture Program.
///
/// This identifies the selected data path, not the mechanism used to observe it. For example, an
/// eBPF counter source observing an xtables Generation still reports `XtablesTproxy`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CapturePathId {
    NftablesTproxy,
    XtablesTproxy,
    ManagedTun,
}

impl CapturePathId {
    pub const ALL: [Self; 3] = [Self::NftablesTproxy, Self::XtablesTproxy, Self::ManagedTun];

    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::NftablesTproxy => "nftables_tproxy",
            Self::XtablesTproxy => "xtables_tproxy",
            Self::ManagedTun => "managed_tun",
        }
    }
}

/// Desired State request for automatic or exact Capture Path selection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CapturePathRequest {
    Auto,
    Exact(CapturePathId),
}

impl CapturePathRequest {
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Exact(path) => path.as_token(),
        }
    }
}

/// Closed inventory of complete mutation Adapters available to the selector.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ImplementedCaptureAdapters {
    nftables_tproxy: bool,
    xtables_tproxy: bool,
    managed_tun: bool,
}

impl ImplementedCaptureAdapters {
    #[must_use]
    pub const fn new(nftables_tproxy: bool, xtables_tproxy: bool, managed_tun: bool) -> Self {
        Self {
            nftables_tproxy,
            xtables_tproxy,
            managed_tun,
        }
    }

    #[must_use]
    pub const fn contains(self, path: CapturePathId) -> bool {
        match path {
            CapturePathId::NftablesTproxy => self.nftables_tproxy,
            CapturePathId::XtablesTproxy => self.xtables_tproxy,
            CapturePathId::ManagedTun => self.managed_tun,
        }
    }

    #[must_use]
    pub fn count(self) -> u8 {
        u8::from(self.nftables_tproxy) + u8::from(self.xtables_tproxy) + u8::from(self.managed_tun)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_path_tokens_are_stable_and_unique() {
        let mut tokens = CapturePathId::ALL.map(CapturePathId::as_token);
        tokens.sort_unstable();
        assert_eq!(tokens, ["managed_tun", "nftables_tproxy", "xtables_tproxy"]);
    }

    #[test]
    fn path_requests_have_one_current_token_grammar() {
        assert_eq!(CapturePathRequest::Auto.as_token(), "auto");
        for path in CapturePathId::ALL {
            assert_eq!(CapturePathRequest::Exact(path).as_token(), path.as_token());
        }
    }

    #[test]
    fn implemented_adapter_inventory_is_closed_over_every_path() {
        let adapters = ImplementedCaptureAdapters::new(false, true, false);
        assert_eq!(adapters.count(), 1);
        assert!(!adapters.contains(CapturePathId::NftablesTproxy));
        assert!(adapters.contains(CapturePathId::XtablesTproxy));
        assert!(!adapters.contains(CapturePathId::ManagedTun));
    }
}
