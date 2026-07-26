# Rust dependency assurance for P1-R2

- Status: implementation-ready policy decision
- Repository state reviewed: `7d514896c8234efe0f144ab9770786916f8b11ee`
- External sources accessed: 2026-07-26
- Locked graph: root workspace `Cargo.lock`, all features and all target-specific dependencies

This note defines the advisory, license, and source gate for Flux's root Rust workspace. It does not
approve the excluded `addrsyncd` development bridge, provide legal advice, or replace final package
SBOM/provenance review.

## Decision

Use `cargo-deny 0.20.2` against the committed lockfile with this required command:

```text
cargo deny --manifest-path Cargo.toml --config deny.toml --all-features --locked \
  check advisories licenses sources
```

CI should download the official x86_64 Linux musl release archive and reject it unless its SHA-256
is exactly `9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f`.
Do not use the official Docker action for this repository: even at pinned action commit
`3c6349835b2b7b196a839186cb8b78e02f7b5f25`, its Dockerfile downloads the cargo-deny release archive
without checking a digest. That is a reasonable general-purpose installation path, but it is weaker
than Flux's existing immutable-input discipline.

The advisory database is intentionally refreshed from the official RustSec repository on every
online run. This means a newly published advisory can fail CI without a Flux source change. That is
the desired required-gate behavior. Record the exact advisory database commit in release evidence;
do not convert advisories to `continue-on-error` merely to stabilize a green badge.

## Required policy

- Deny vulnerable and unsound advisories across the complete selected graph.
- Deny unmaintained advisories for direct workspace dependencies.
- Deny yanked versions and require that configured advisory exceptions remain in use. The initial
  policy has no advisory exceptions.
- Enable development dependencies for license inspection and deny every license expression that
  cannot be satisfied by the explicit allowlist.
- Allow `Apache-2.0`, `BSD-3-Clause`, `GPL-3.0-only`, `ISC`, `MIT`, `Unicode-3.0`, and `Zlib`.
- Allow `CDLA-Permissive-2.0` only for exact package `webpki-roots@1.0.9`. Its crates.io record
  identifies it as Mozilla CA root-certificate data and publishes checksum
  `7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a`.
- Deny unknown registries and all Git dependencies. Permit only the canonical crates.io index.
- Treat unused allowed licenses, license exceptions, and sources as errors so policy does not grow
  stale or accumulate speculative allowances.

## Observed locked graph

The verified `cargo-deny 0.20.2` binary reported 113 packages: five GPL-3.0-only workspace members,
108 registry packages, and no Git packages. Advisories and sources passed on the first policy run.
The first license run rejected only:

1. the five Flux workspace members because `GPL-3.0-only` was not yet in the explicit allowlist;
2. `webpki-roots 1.0.9` because its sole expression is `CDLA-Permissive-2.0`.

After adding GPL-3.0-only and the exact `webpki-roots` exception, advisories, licenses, and sources
all passed. No runtime dependency or lockfile changed. The fetched RustSec database resolved to
commit `29638ff054fdbb83d2844240f7ef7e576cb52629` (2026-07-25).

Other expressions visible in the graph, including `0BSD`, `Apache-2.0 WITH LLVM-exception`,
`LGPL-2.1-or-later`, and `Unlicense`, occur only as alternatives to an allowed expression for their
current crate. They are not globally allowed. A dependency update that removes the allowed branch
will therefore fail and require a new review.

## Boundary and limitations

- `addrsyncd/Cargo.toml` is outside the workspace and declares `UNLICENSED`. The Rust-only package
  forbids its binary, while the active development bridge retains it as a rollback artifact. A root
  workspace cargo-deny pass must never be presented as approval of that bridge license.
- This gate checks Cargo metadata and the RustSec advisory database. It does not generate the final
  SPDX package SBOM, verify Sing-Box or Magisk glue licenses, prove reproducible builds, or sign an
  artifact.
- cargo-deny documents that `--locked` rejects lockfile drift, while online advisory fetching keeps
  security knowledge current. Tool/archive reproducibility and advisory-data freshness are separate
  properties and should remain separately reported.
- License configuration is an engineering policy input, not legal advice. Any new license class or
  exception requires explicit review rather than a generic permissive-category shortcut.

## Primary sources

- [cargo-deny 0.20.2 release](https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.20.2)
- [cargo-deny 0.20.2 README and MSRV](https://github.com/EmbarkStudios/cargo-deny/blob/bca0dde53651ee946720e4540b5ce2610bec8f06/README.md)
- [Locked/offline and graph CLI options](https://github.com/EmbarkStudios/cargo-deny/blob/bca0dde53651ee946720e4540b5ce2610bec8f06/docs/src/cli/common.md)
- [Advisory configuration](https://github.com/EmbarkStudios/cargo-deny/blob/bca0dde53651ee946720e4540b5ce2610bec8f06/docs/src/checks/advisories/cfg.md)
- [License configuration](https://github.com/EmbarkStudios/cargo-deny/blob/bca0dde53651ee946720e4540b5ce2610bec8f06/docs/src/checks/licenses/cfg.md)
- [Source configuration](https://github.com/EmbarkStudios/cargo-deny/blob/bca0dde53651ee946720e4540b5ce2610bec8f06/docs/src/checks/sources/cfg.md)
- [Pinned action Dockerfile considered and rejected](https://github.com/EmbarkStudios/cargo-deny-action/blob/3c6349835b2b7b196a839186cb8b78e02f7b5f25/Dockerfile)
- [RustSec advisory database at the audited commit](https://github.com/RustSec/advisory-db/tree/29638ff054fdbb83d2844240f7ef7e576cb52629)
- [RustSec database purpose and format](https://github.com/RustSec/advisory-db/blob/29638ff054fdbb83d2844240f7ef7e576cb52629/README.md)
- [crates.io record for webpki-roots 1.0.9](https://crates.io/api/v1/crates/webpki-roots/1.0.9)
