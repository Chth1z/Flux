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
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::NftablesTproxy => "nftables_tproxy",
            Self::XtablesTproxy => "xtables_tproxy",
            Self::ManagedTun => "managed_tun",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_path_tokens_are_stable_and_unique() {
        let paths = [
            CapturePathId::NftablesTproxy,
            CapturePathId::XtablesTproxy,
            CapturePathId::ManagedTun,
        ];
        let mut tokens = paths.map(CapturePathId::as_token);
        tokens.sort_unstable();
        assert_eq!(tokens, ["managed_tun", "nftables_tproxy", "xtables_tproxy"]);
    }
}
