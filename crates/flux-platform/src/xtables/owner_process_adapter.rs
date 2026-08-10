use std::ffi::{CStr, CString};
use std::time::Instant;

use flux_core::{InterfaceIndex, InterfaceName};

use crate::netlink::policy_routing::{ManagedInterfaceIdentity, PolicyRoutingMutation};
use crate::netlink::policy_routing_session::{PolicyRoutingSession, PolicyRoutingStepOutcome};
use crate::netlink::route_lookup::{CanaryRouteLookupOutcome, CanaryRouteLookupRequest};

use super::super::{XtablesRestoreArtifact, XtablesRestoreFamily};
use super::{
    NativeMutationCertainty, NativePolicyRoutingObservation, NativeXtablesAdapterError,
    NativeXtablesCanaryCounterReadback, NativeXtablesOwnerAdapter,
};
use crate::netlink::policy_routing::ManagedPolicyRoutingIdentity;
use crate::xtables::native::{
    XtablesRestoreMutationDisposition, XtablesRestoreProcessError, XtablesToolSetProcessAdapter,
};
use crate::xtables::native_capture::{
    NativeCaptureCanaryRouteObservation, NativeCaptureCanaryRouteOutcome,
    NativeCaptureCanaryRouteQuery, NativeCaptureCanaryRouteRejection,
};
use crate::xtables::save::counted::project_expected_counted_chain;
use crate::xtables::save::{
    XtablesExpectedState, XtablesSaveProjection, XtablesSaveProjectionError, project_xtables_save,
};

/// Real process/netlink Adapter for the private owner.
///
/// Constructing this Adapter still does not construct an admitted production target. The only
/// current positive target constructor is test-only, so production composition remains fail-closed.
pub(crate) struct NativeXtablesProcessOwnerAdapter {
    tools: XtablesToolSetProcessAdapter,
}

impl NativeXtablesProcessOwnerAdapter {
    #[must_use]
    pub(crate) const fn new(tools: XtablesToolSetProcessAdapter) -> Self {
        Self { tools }
    }

    #[cfg(test)]
    pub(crate) fn into_tools(self) -> XtablesToolSetProcessAdapter {
        self.tools
    }
}

impl NativeXtablesOwnerAdapter for NativeXtablesProcessOwnerAdapter {
    fn tool_digest(&self) -> [u8; 32] {
        *self.tools.identity().digest().as_bytes()
    }

    fn validate_interface_identity(
        &mut self,
        identity: ManagedInterfaceIdentity,
    ) -> Result<(), NativeXtablesAdapterError> {
        validate_system_interface_identity(identity.name(), identity.index()).map_err(|detail| {
            NativeXtablesAdapterError::new(
                "validate loopback interface identity",
                NativeMutationCertainty::NotMutated,
                detail,
            )
        })
    }

    fn restore(
        &mut self,
        family: XtablesRestoreFamily,
        artifact: &XtablesRestoreArtifact,
    ) -> Result<(), NativeXtablesAdapterError> {
        if artifact.context().family() != family {
            return Err(NativeXtablesAdapterError::new(
                "xtables restore family validation",
                NativeMutationCertainty::NotMutated,
                "artifact family differs from the owner-selected family",
            ));
        }
        self.tools
            .restore(artifact)
            .map(|_| ())
            .map_err(map_restore)
    }

    fn observe_xtables(
        &mut self,
        family: XtablesRestoreFamily,
    ) -> Result<XtablesSaveProjection, NativeXtablesAdapterError> {
        let output = self.tools.save(family).map_err(map_restore)?;
        project_complete_save(output.stdout(), family).map_err(|error| {
            let mut detail = match std::error::Error::source(&error) {
                Some(source) => format!("{error}: {source}"),
                None => error.to_string(),
            };
            if let Some(line) = error
                .line()
                .and_then(|line| save_line(output.stdout(), line))
                && line.contains("FLX")
            {
                detail.push_str("; live native line: ");
                detail.push_str(line);
            }
            NativeXtablesAdapterError::new(
                "xtables-save projection",
                NativeMutationCertainty::NotMutated,
                detail.into_boxed_str(),
            )
        })
    }

    fn observe_canary_counters(
        &mut self,
        family: XtablesRestoreFamily,
        expected: &XtablesExpectedState,
        observation_chain: &str,
    ) -> Result<NativeXtablesCanaryCounterReadback, NativeXtablesAdapterError> {
        let output = self.tools.save_with_counters(family).map_err(map_restore)?;
        project_canary_counter_readback(output.stdout(), family, expected, observation_chain)
    }

    fn mutate_policy_routing(
        &mut self,
        mutation: PolicyRoutingMutation,
    ) -> Result<(), NativeXtablesAdapterError> {
        let mut session = PolicyRoutingSession::open().map_err(|error| {
            NativeXtablesAdapterError::new(
                "open policy-routing session",
                NativeMutationCertainty::NotMutated,
                error.to_string(),
            )
        })?;
        let receipt = session.mutate_one(mutation).map_err(|error| {
            NativeXtablesAdapterError::new(
                "policy-routing mutation setup",
                NativeMutationCertainty::NotMutated,
                error.to_string(),
            )
        })?;
        match receipt.outcome() {
            PolicyRoutingStepOutcome::Accepted(_) => Ok(()),
            PolicyRoutingStepOutcome::Rejected(ack) => Err(NativeXtablesAdapterError::new(
                "policy-routing mutation",
                NativeMutationCertainty::NotMutated,
                format!("kernel rejected request: {ack:?}").into_boxed_str(),
            )),
            PolicyRoutingStepOutcome::NotSent(error) => Err(NativeXtablesAdapterError::new(
                "policy-routing mutation",
                NativeMutationCertainty::NotMutated,
                error.to_string(),
            )),
            PolicyRoutingStepOutcome::MayHaveMutated(error) => Err(NativeXtablesAdapterError::new(
                "policy-routing mutation",
                NativeMutationCertainty::MayHaveMutated,
                error.to_string(),
            )),
        }
    }

    fn observe_policy_routing(
        &mut self,
        identity: ManagedPolicyRoutingIdentity,
    ) -> Result<NativePolicyRoutingObservation, NativeXtablesAdapterError> {
        // Observation always starts on a fresh groups-zero socket, which is required after any
        // ambiguous ACK and prevents a poisoned mutation session from authorizing readback.
        let mut session = PolicyRoutingSession::open().map_err(|error| {
            NativeXtablesAdapterError::new(
                "open policy-routing observation session",
                NativeMutationCertainty::NotMutated,
                error.to_string(),
            )
        })?;
        let observed = session.observe(identity).map_err(|error| {
            NativeXtablesAdapterError::new(
                "policy-routing readback",
                NativeMutationCertainty::NotMutated,
                error.to_string(),
            )
        })?;
        Ok(NativePolicyRoutingObservation::new(
            observed.route().exact_count(),
            observed.route().conflict_count(),
            observed.rule().exact_count(),
            observed.rule().conflict_count(),
        ))
    }

    fn observe_canary_route(
        &mut self,
        query: NativeCaptureCanaryRouteQuery,
    ) -> Result<NativeCaptureCanaryRouteOutcome, NativeXtablesAdapterError> {
        // Every lookup gets a fresh groups-zero socket. An ambiguous receive therefore cannot
        // contaminate a later family or attempt, and the subscribed inventory socket is untouched.
        let mut session = PolicyRoutingSession::open().map_err(|error| {
            NativeXtablesAdapterError::new(
                "open canary route-lookup session",
                NativeMutationCertainty::NotMutated,
                error.to_string(),
            )
        })?;
        let lookup = CanaryRouteLookupRequest::new(
            query.destination().ip(),
            query.responder_port(),
            query.uid(),
            query.mark(),
        );
        let outcome = session
            .lookup_canary_route_until(lookup, query.deadline())
            .map_err(|error| {
                NativeXtablesAdapterError::new(
                    "canary route lookup",
                    NativeMutationCertainty::NotMutated,
                    error.to_string(),
                )
            })?;
        let observed_at = Instant::now();
        if observed_at >= query.deadline() {
            return Err(NativeXtablesAdapterError::new(
                "canary route lookup completion",
                NativeMutationCertainty::NotMutated,
                "route lookup completed at or after the immutable canary deadline",
            ));
        }
        Ok(match outcome {
            CanaryRouteLookupOutcome::Resolved(result) => {
                NativeCaptureCanaryRouteOutcome::Resolved(NativeCaptureCanaryRouteObservation::new(
                    query,
                    result.table(),
                    observed_at,
                ))
            }
            CanaryRouteLookupOutcome::Rejected(rejection) => {
                NativeCaptureCanaryRouteOutcome::Rejected(NativeCaptureCanaryRouteRejection::new(
                    rejection.errno(),
                ))
            }
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn validate_system_interface_identity(
    name: InterfaceName,
    index: InterfaceIndex,
) -> Result<(), Box<str>> {
    let name_c = CString::new(name.as_bytes())
        .map_err(|_| Box::<str>::from("bound interface name contains an interior NUL"))?;
    // SAFETY: `name_c` is a readable NUL-terminated interface name for the duration of the call.
    let resolved_index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };
    if resolved_index == 0 {
        return Err(format!(
            "cannot resolve bound interface name {:?}: {}",
            name.as_bytes(),
            std::io::Error::last_os_error()
        )
        .into_boxed_str());
    }
    if resolved_index != index.get() {
        return Err(format!(
            "bound interface name {:?} now resolves to index {resolved_index}, expected {}",
            name.as_bytes(),
            index.get()
        )
        .into_boxed_str());
    }

    let mut resolved_name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `resolved_name` is writable for IF_NAMESIZE bytes and `index` is in Linux's positive
    // interface-index domain. A non-null result points into `resolved_name`.
    let resolved = unsafe { libc::if_indextoname(index.get(), resolved_name.as_mut_ptr()) };
    if resolved.is_null() {
        return Err(format!(
            "cannot resolve bound interface index {}: {}",
            index.get(),
            std::io::Error::last_os_error()
        )
        .into_boxed_str());
    }
    // SAFETY: successful `if_indextoname` writes a NUL-terminated name into `resolved_name`.
    let resolved_name = unsafe { CStr::from_ptr(resolved) }.to_bytes();
    if resolved_name != name.as_bytes() {
        return Err(format!(
            "bound interface index {} now names {:?}, expected {:?}",
            index.get(),
            resolved_name,
            name.as_bytes()
        )
        .into_boxed_str());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn validate_system_interface_identity(
    _name: InterfaceName,
    _index: InterfaceIndex,
) -> Result<(), Box<str>> {
    Err("live interface identity validation is unsupported on this platform".into())
}

fn save_line(stdout: &[u8], line: usize) -> Option<&str> {
    let text = std::str::from_utf8(stdout).ok()?;
    text.lines().nth(line.checked_sub(1)?)
}

fn project_complete_save(
    stdout: &[u8],
    family: XtablesRestoreFamily,
) -> Result<XtablesSaveProjection, XtablesSaveProjectionError> {
    // Legacy xtables emits exactly zero bytes in a fresh network namespace where no table has
    // been initialized. That is stronger clean-absence evidence than a missing mangle section in
    // otherwise nonempty output. Normalize only this exact zero-table shape; every nonempty save
    // still passes through the strict full-save grammar unchanged.
    if stdout.is_empty() {
        project_xtables_save(b"*mangle\nCOMMIT\n", family)
    } else {
        project_xtables_save(stdout, family)
    }
}

fn project_canary_counter_readback(
    stdout: &[u8],
    family: XtablesRestoreFamily,
    expected: &XtablesExpectedState,
    observation_chain: &str,
) -> Result<NativeXtablesCanaryCounterReadback, NativeXtablesAdapterError> {
    let packets = project_expected_counted_chain(stdout, family, expected, observation_chain)
        .map_err(|error| {
            let mut detail = match std::error::Error::source(&error) {
                Some(source) => format!("{error}: {source}"),
                None => error.to_string(),
            };
            if let Some(line) = error.line().and_then(|line| save_line(stdout, line))
                && line.contains("FLX")
            {
                detail.push_str("; live native line: ");
                detail.push_str(line);
            }
            NativeXtablesAdapterError::new(
                "counted xtables-save projection",
                NativeMutationCertainty::NotMutated,
                detail.into_boxed_str(),
            )
        })?;
    let [capture_packets, recapture_packets, bypass_packets] = packets.as_slice() else {
        return Err(NativeXtablesAdapterError::new(
            "counted xtables-save projection",
            NativeMutationCertainty::NotMutated,
            "the exact canary observation chain did not contain three rules",
        ));
    };
    Ok(NativeXtablesCanaryCounterReadback::new(
        *capture_packets,
        *recapture_packets,
        *bypass_packets,
    ))
}

fn map_restore(error: XtablesRestoreProcessError) -> NativeXtablesAdapterError {
    let certainty = match error.mutation_disposition() {
        XtablesRestoreMutationDisposition::NotStarted => NativeMutationCertainty::NotMutated,
        XtablesRestoreMutationDisposition::MayHaveMutated => {
            NativeMutationCertainty::MayHaveMutated
        }
    };
    NativeXtablesAdapterError::new("xtables process", certainty, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtables::save::XtablesExpectedStatePhase;
    use crate::xtables::{XtablesRestoreAction, XtablesRestoreContext, parse_xtables_restore};

    #[test]
    fn exactly_empty_full_save_is_clean_absence_but_nonempty_missing_mangle_stays_invalid() {
        assert!(
            project_complete_save(b"", XtablesRestoreFamily::Ipv4)
                .unwrap()
                .is_empty()
        );
        assert!(project_complete_save(b"*filter\nCOMMIT\n", XtablesRestoreFamily::Ipv4).is_err());
    }

    #[test]
    fn counted_canary_projection_maps_exact_rule_order_and_rejects_malformed_readback() {
        const CHAIN: &str = "FLX4A0000000007";
        let artifact = parse_xtables_restore(
            format!(
                "*mangle\n:{CHAIN} - [0:0]\n\
                 -A {CHAIN} -m owner --uid-owner 2000 -m mark --mark 0x200000/0x600000 -j RETURN\n\
                 -A {CHAIN} -m owner --uid-owner 1000 -m mark --mark 0x200000/0x600000 -j RETURN\n\
                 -A {CHAIN} -m owner --uid-owner 1000 -j RETURN\n\
                 COMMIT\n"
            )
            .as_bytes(),
            XtablesRestoreContext::new(XtablesRestoreAction::Apply, XtablesRestoreFamily::Ipv4),
        )
        .unwrap();
        let expected = XtablesExpectedState::from_apply_artifacts(
            XtablesRestoreFamily::Ipv4,
            XtablesExpectedStatePhase::Active,
            [&artifact],
        )
        .unwrap();
        let counted = format!(
            "*mangle\n:{CHAIN} - [0:0]\n\
             [3:180] -A {CHAIN} -m owner --uid-owner 2000 -m mark --mark 0x200000/0x600000 -j RETURN\n\
             [5:300] -A {CHAIN} -m owner --uid-owner 1000 -m mark --mark 0x200000/0x600000 -j RETURN\n\
             [7:420] -A {CHAIN} -m owner --uid-owner 1000 -j RETURN\n\
             COMMIT\n"
        );

        assert_eq!(
            project_canary_counter_readback(
                counted.as_bytes(),
                XtablesRestoreFamily::Ipv4,
                &expected,
                CHAIN,
            )
            .unwrap(),
            NativeXtablesCanaryCounterReadback::new(3, 5, 7)
        );

        let malformed = counted.replacen(&format!("[5:300] -A {CHAIN}"), &format!("-A {CHAIN}"), 1);
        let error = project_canary_counter_readback(
            malformed.as_bytes(),
            XtablesRestoreFamily::Ipv4,
            &expected,
            CHAIN,
        )
        .expect_err("a missing counted prefix must not authorize canary evidence");
        assert_eq!(error.certainty(), NativeMutationCertainty::NotMutated);
        assert!(error.to_string().contains("MissingRuleCounter"));
        assert!(error.to_string().contains("live native line"));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn live_interface_identity_validation_checks_name_and_index() {
        let name = InterfaceName::new(b"lo").unwrap();
        let name_c = CString::new(name.as_bytes()).unwrap();
        // SAFETY: `name_c` is a readable NUL-terminated interface name for this call.
        let raw_index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };
        assert_ne!(raw_index, 0, "test environment must expose loopback 'lo'");
        let index = InterfaceIndex::new(raw_index).unwrap();

        validate_system_interface_identity(name, index).unwrap();
        assert!(
            validate_system_interface_identity(
                InterfaceName::new(b"flux-missing").unwrap(),
                index,
            )
            .is_err()
        );
        assert!(
            validate_system_interface_identity(
                name,
                InterfaceIndex::new(i32::MAX as u32).unwrap(),
            )
            .is_err()
        );
    }
}
