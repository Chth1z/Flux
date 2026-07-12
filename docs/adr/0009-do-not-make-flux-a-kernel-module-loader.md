---
status: accepted
decision_date: 2026-07-13
---

# Do not make Flux a kernel-module loader

Production Flux will not package `.ko`, KPM, or opaque kernel payloads and will not call `init_module`, `finit_module`, or `delete_module`. Kernel module support in an Android base config does not prove exact KMI, exported-symbol, modversion, signature, SELinux, AVB/DLKM, hook, or teardown compatibility. A module can panic or corrupt the running kernel, and userspace compensation cannot guarantee recovery of the current boot.

An already-loaded, reviewed OEM/custom-kernel extension may be consumed only as optional exact-device read-only observation. It requires a freshness-bound extension profile, independently observed AVB/module-signature/measurement evidence matching a reviewed identity catalog or explicit expert trust record, a versioned and strictly validated control protocol, and a nonpersistent behavioral canary. Generic Netlink sender/sequence/nonce checks prove origin and correlation, not the module's claimed source digest. The extension is not part of `BackendPlan` or a Generation. Flux never unloads an extension it did not load, and production Flux loads none.

Positive acceleration, custom direct Capture Paths, custom xtables/nft expressions, new BPF helpers/kfuncs, and APatch KPM/inline/syscall hooks remain lab-only. A future decision-bearing exception requires a superseding ADR with a concrete exact-device partner, passive-by-default Generation lease and heartbeat expiry, verified enable/disable canaries, complete conventional fallback, reproducible source/SBOM/signing lifecycle, boot-loop quarantine, staged initialization and RCU-safe teardown, and release evidence that justifies the kernel-wide failure radius.
