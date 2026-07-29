use fluxd::{CapturePathDecision, CapturePathSelection};

pub(crate) fn xtables_capture_path_selection() -> CapturePathSelection {
    serde_json::from_value(serde_json::json!({
        "request": "auto",
        "selected": "xtables_tproxy",
        "reason": "automatic_highest_ranked_qualified",
        "candidates": [
            {
                "path": "nftables_tproxy",
                "state": "unimplemented",
                "qualification_state": "unqualified",
                "first_kernel_gap": null
            },
            {
                "path": "xtables_tproxy",
                "state": "qualified",
                "qualification_state": "qualified",
                "first_kernel_gap": null
            },
            {
                "path": "managed_tun",
                "state": "unimplemented",
                "qualification_state": "unqualified",
                "first_kernel_gap": null
            }
        ],
        "evidence_digest": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
    }))
    .expect("canonical xtables Capture Path selection fixture")
}

pub(crate) fn xtables_capture_path_decision() -> CapturePathDecision {
    CapturePathDecision::Selected {
        selection: xtables_capture_path_selection(),
    }
}

#[allow(
    dead_code,
    reason = "shared fixture is used only by integration targets that exercise rejection"
)]
pub(crate) fn unqualified_capture_path_decision() -> CapturePathDecision {
    serde_json::from_value(serde_json::json!({
        "outcome": "rejected",
        "rejection": {
            "request": "auto",
            "reason": {
                "kind": "no_qualified_path"
            },
            "candidates": [
                {
                    "path": "nftables_tproxy",
                    "state": "unimplemented",
                    "qualification_state": "unqualified",
                    "first_kernel_gap": null
                },
                {
                    "path": "xtables_tproxy",
                    "state": "unqualified",
                    "qualification_state": "unqualified",
                    "first_kernel_gap": null
                },
                {
                    "path": "managed_tun",
                    "state": "unimplemented",
                    "qualification_state": "unqualified",
                    "first_kernel_gap": null
                }
            ],
            "evidence_digest": "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"
        }
    }))
    .expect("canonical unqualified Capture Path decision fixture")
}
