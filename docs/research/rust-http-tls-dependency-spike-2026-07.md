# Rust HTTP/TLS dependency spike for `P0-B1`

- Status: recommended dependency decision, pending explicit production-dependency approval
- Repository state reviewed: `d4b08be1898d42e36b435a6416c35e1be0bc1715`
- Candidate releases: `ureq 3.3.0` and `minreq 3.0.0`
- External sources accessed: 2026-07-26
- Target: synchronous retrieval in the standalone Magisk `fluxd` process

This note supports [roadmap item `P0-B1`](../architecture/implementation-roadmap.md) and does not
change the release or Android qualification gates. Facts below come from the exact published crate
releases, their pinned upstream revisions, official Android/Rust documentation, and the RustSec
advisory database. Recommendations are Flux decisions derived from those facts.

## Decision

**Select `ureq 3.3.0` with Rustls, static WebPKI roots, gzip, and Brotli.** Add it only when the
bounded subscription fetcher is implemented, with this exact direct dependency:

```toml
ureq = { version = "=3.3.0", default-features = false, features = ["rustls", "gzip", "brotli"] }
```

Do not enable `platform-verifier`, `native-tls`, `vendored`, `socks-proxy`, `cookies`, `charset`,
`json`, or `multipart`. Keep retrieval blocking and run it in the existing bounded worker model;
this task does not justify an async runtime.

`ureq` is not the resource-policy boundary by itself. A Flux-owned fetcher must enforce the URL,
redirect, deadline, encoded-body, decoded-body, content-type, parsed-node, and publication limits.
The crate is the blocking HTTP/1.1 and TLS adapter behind that interface.

The decision is conditional on one supply-chain gate: the committed Flux lockfile must resolve
`rustls-webpki >= 0.103.13`, and the resulting graph must pass the project's vulnerability and
license checks. The lockfiles published with the candidates are not suitable dependency locks for
Flux.

## Existing contract

The shell updater currently invokes `curl -L -f -s --http1.1 --compressed`, with the same configured
value used for connection and whole-operation timeouts. It follows redirects, rejects HTTP error
status, and negotiates compressed responses, but it does not enforce the configured 16 MiB body
limit. [L-UPDATER] The schema currently defaults to a 10-second download timeout, a 16 MiB maximum
download, and 10,000 parsed nodes. [L-SPEC]

The Rust replacement must improve that behavior without moving network I/O onto the daemon reactor:

1. accept only an absolute HTTPS URL without embedded credentials;
2. apply one wall-clock deadline across DNS, connection, TLS, redirects, headers, and body reads;
3. follow at most five redirects, require HTTPS at every hop, and never forward authorization;
4. ignore ambient proxy environment variables unless a future typed Flux setting explicitly opts in;
5. reject oversized response headers and unsupported status/content encodings/content types;
6. bound encoded entity bytes before gzip/Brotli decoding and decoded bytes after decoding;
7. bound parsing and normalization by `max_nodes` and other format-specific limits;
8. validate and publish atomically, retaining the active snapshot after every failure.

Here, "encoded body" means HTTP entity-body octets after transfer framing and before content
decoding. It does not mean TLS records, HTTP headers, or chunk framing. This is the stable quantity
available through the selected public body API; Flux must not call it a whole-socket wire limit.

## Candidate comparison

| Criterion | `ureq 3.3.0` | `minreq 3.0.0` | Flux consequence |
|---|---|---|---|
| I/O model | Blocking; no async runtime; crate forbids unsafe code [U-LIB] | Blocking [M-LIB] | Both fit the retained worker model |
| MSRV | Rust 1.85 [U-MANIFEST] | Rust 1.63 [M-MANIFEST] | Both are below workspace Rust 1.93 |
| Upstream posture | Active 3.x client with a semver-stable main API; connector/resolver APIs are explicitly `unversioned` [U-LIB] | Manifest says `passively-maintained`; docs assume well-behaved servers and recommend a more robust client for untested servers [M-MANIFEST] [M-LIB] | Subscription endpoints are untrusted, so `ureq` is the safer ownership base |
| Rustls selection | `rustls` disables Rustls defaults, selects `ring`, and selects static `webpki-roots` [U-MANIFEST] | `https-rustls` enables Rustls with its defaults plus static `webpki-roots` [M-MANIFEST] | The observed minreq graph selected `aws-lc-rs/aws-lc-sys`; ureq has the narrower intended provider |
| Compression | Built-in gzip and Brotli negotiation/decoding features [U-LIB] | No gzip or Brotli feature [M-MANIFEST] | `minreq` cannot preserve current `--compressed` behavior without extra code/dependencies |
| Timeouts | Global, per-call, resolve, connect/TLS, request, response-header, and response-body durations [U-CONFIG] | One whole-second deadline from `with_timeout` or `MINREQ_TIMEOUT` [M-REQUEST] [M-CONNECTION] | `ureq` expresses the required global deadline and phase diagnostics directly |
| DNS timeout behavior | Resolver timeout is part of the configured timing model [U-CONFIG] | Spawns a thread around work that includes resolution; on timeout the join handle is dropped while the work may continue [M-CONNECTION] | Repeated stuck resolutions can leave detached minreq work running |
| Redirects | Finite configurable maximum; `0` disables; HTTPS-only applies to redirects; authorization is removed by default [U-CONFIG] [U-RUN] | Default maximum 100; recursive handling; only 301/302/303/307; no HTTPS-only guard [M-REQUEST] [M-CONNECTION] | `minreq` needs a complete Flux-owned redirect loop before it is safe |
| Cross-origin headers | `RedirectAuthHeaders::Never` is the default [U-CONFIG] | The request configuration and headers are retained when the parsed target changes [M-REQUEST] | `minreq` can carry credentials across hosts unless Flux strips them manually |
| Encoded body limit | Public streaming body limit exists; it wraps the body source before content decoding [U-BODY] | `send()` reads the complete body into an unbounded `Vec`; only `send_lazy()` exposes `Read` [M-REQUEST] [M-RESPONSE] | Both need Flux-owned decoded limits; ureq supplies the first encoded layer |
| Proxy environment | Defaults read `ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY`; `.proxy(None)` disables that [U-CONFIG] [U-PROXY] | Optional proxy support reads environment variables when no explicit proxy is set, has no `NO_PROXY`, and exposes no explicit ignore-environment state [M-REQUEST] | Flux must set `ureq` proxy to `None`; do not enable minreq proxy support |
| Test substitution | Custom connector and resolver exist, but under the non-semver `unversioned` API [U-AGENT] [U-LIB] | No transport/resolver injection API | Own a stable Flux fetcher trait and test normal HTTP behavior with loopback servers |
| License | MIT OR Apache-2.0 [U-MANIFEST] | ISC [M-MANIFEST] | Both are compatible inputs to review; the full resolved graph still needs notices/SBOM |

`minreq` has the smaller HTTPS-only dependency graph, but that is not the product cost. Equivalent
compression, redirect security, two-layer limits, finer timing, and test substitution would all
become Flux code or extra dependencies. Its own warning about untested servers is directly at odds
with a public subscription downloader. The smaller core does not compensate for the missing policy
surface.

## Required `ureq` configuration

Create one private agent for subscription retrieval. Do not use crate-level convenience functions,
because their default configuration reads proxy environment state and permits HTTP:

```rust
let config = ureq::Agent::config_builder()
    .https_only(true)
    .proxy(None)
    .max_redirects(5)
    .max_redirects_will_error(true)
    .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
    .timeout_global(Some(download_timeout))
    .timeout_resolve(Some(download_timeout))
    .timeout_connect(Some(download_timeout))
    .timeout_recv_response(Some(download_timeout))
    .timeout_recv_body(Some(download_timeout))
    .max_response_header_size(64 * 1024)
    .build();
let agent = ureq::Agent::new_with_config(config);
```

The exact builder path must be compiled against `3.3.0` during implementation; the configuration
values above are the required policy, not a promise to expose `ureq` types outside the adapter.
`timeout_global` is the authoritative wall-clock limit across redirects. Phase timeouts provide
bounded failure classification but must never extend that deadline.

Before calling the agent, parse the URL structurally and reject:

- a scheme other than `https`;
- missing host, URL credentials, or a fragment;
- a non-default port unless the product schema deliberately allows it;
- control characters or a URL above the configured input-length bound.

After receiving headers, accept only successful `2xx` responses. Define a narrow content-type
allowlist for the formats B1 actually parses; missing or generic binary types may be admitted only
through an explicit compatibility rule backed by fixtures. Reject stacked or unknown
`Content-Encoding` values rather than passing ambiguous bytes to parsers.

### Two-layer body budget

`BodyWithConfig::limit` is below `ContentDecoder`: it limits the encoded entity source and the gzip
or Brotli decoder reads through that limiter. [U-BODY] Its limiter reports an error when no budget
remains before making the next EOF probe. Therefore an inclusive `max_encoded` policy requires:

1. checked computation of `max_encoded + 1`;
2. `body.into_with_config().limit(max_encoded + 1).reader()`;
3. a Flux-owned decoded reader/collector that reads at most `max_decoded + 1` bytes;
4. rejection when the decoded count exceeds `max_decoded`, before parsing or publication.

This permits exactly `max_encoded` bytes to reach EOF but rejects an encoded body of
`max_encoded + 1` bytes. The second counter catches decompression bombs. Do not rely on
`Content-Length`: chunked and close-delimited bodies may omit it, and a compressed length says
nothing about decoded size.

Keep separate typed counters in the fetch result:

| Stage | Required bound |
|---|---|
| URL and response headers | Explicit small byte limits |
| Redirect traversal | Five hops within one global deadline |
| Encoded entity body | Existing `max_download_bytes`, inclusive |
| Decoded body | New explicit schema field; initially no larger than the accepted implementation budget |
| Parsed records/nodes | Existing `max_nodes`, plus per-field/string bounds |
| Normalized configuration | Bounded serialized size before Sing-Box validation |
| Persisted assets/history | Content-addressed active snapshot plus one bounded known-good predecessor |

Do not silently reuse `max_download_bytes` as both encoded and decoded limits without recording that
compatibility decision in the schema. The two limits defend different amplification stages.

## TLS and Android trust decision

Use the `rustls` feature's `ring` provider and compiled `webpki-roots`. This is appropriate for the
current standalone native Magisk process because it has no Android application JVM, `Context`, AAR,
Gradle, or Kotlin packaging layer.

Do not enable `platform-verifier`. On Android, `rustls-platform-verifier 0.6.2` requires a Kotlin
component in an Android application build, JVM/context handles, and one-time `init_hosted` or
`init_external` initialization before networking. [RPV] Adding that hosting surface solely for
subscription TLS would work against the Rust-unification goal.

Static roots have explicit product consequences:

- Android user-installed, enterprise, and locally administered roots are not trusted;
- CA additions and removals arrive only through a Flux dependency/package update;
- Android platform distrust and revocation behavior is not inherited;
- private subscription endpoints require a future typed custom-CA design, not an implicit system
  store fallback or disabled certificate verification.

Never provide an insecure certificate-verification switch. If Android-native trust becomes a hard
requirement, reopen this decision around a deliberately hosted verifier bridge or a narrowly owned
custom-root input, with packaging and lifecycle costs measured separately.

## Android build spike

Both exact candidates were cross-checked successfully with Rust 1.93 and NDK
`27.3.13750724` for `aarch64-linux-android`:

- `ureq 3.3.0`: `default-features = false`, features `rustls,gzip,brotli`;
- `minreq 3.0.0`: feature `https-rustls`.

Because both selected crypto providers compile target-native code, a fresh Android `cargo check`
requires the API-suffixed NDK compiler as well as the Rust standard-library target. The canonical
`xtask` check must bind that compiler explicitly; an unsuffixed
`aarch64-linux-android-clang` cannot be assumed to exist on `PATH`.

The ureq target selected `ring`; the minreq target selected `aws-lc-rs` and `aws-lc-sys`, including
their C/CMake build surface. AWS-LC-RS lists Android as supported, so this is a cost difference, not
an Android incompatibility. [AWS-LC]

This result proves only that the selected graphs compile for the target. No ARM64 device was
available, and WSA is x86_64 mechanism evidence rather than ARM64 or release qualification. Runtime
DNS, TLS handshake, root acceptance, redirects, compressed limits, process memory, and 16 KB ELF
alignment remain implementation/qualification gates. Rust's Android target is Tier 2 and requires
the Android NDK toolchain. [RUST-ANDROID]

## Security and supply chain

The inspected RustSec database was commit
`29638ff054fdbb83d2844240f7ef7e576cb52629` dated 2026-07-25. The crate-published locks resolved
`rustls-webpki 0.103.10` for ureq and `0.103.11` for minreq. Both versions fall below fixes for
`RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, and `RUSTSEC-2026-0104`; `0.103.13` is the first 0.103.x
release satisfying all three patched ranges. [RS-0098] [RS-0099] [RS-0104]

A fresh resolution to `rustls-webpki 0.103.13` succeeded for each candidate. B1 must therefore:

1. commit a lockfile resolving `rustls-webpki >= 0.103.13`;
2. run `cargo audit` against a current advisory database in CI and release qualification;
3. run the repository license policy and emit third-party notices/SBOM entries;
4. review updates to `ureq`, Rustls, `ring`, `webpki-roots`, `flate2`, and
   `brotli-decompressor` as security-relevant changes;
5. retain exact versions or an explicitly reviewed update policy rather than depending on an
   unexamined floating resolution.

The selected graph is permissively licensed. Notable nonstandard expressions include
`webpki-roots` certificate data under `CDLA-Permissive-2.0` and `ring` under
`Apache-2.0 AND ISC`; they still require the repository's normal policy and notice review.

## Implementation boundary and tests

Place `ureq` behind a narrow Flux-owned synchronous interface. Domain code should receive a request
policy and return bounded bytes plus sanitized metadata; it should not depend on `ureq::Agent`,
response bodies, or error variants. This keeps retry, snapshot retention, parsing, validation, and
publication independent of the HTTP library and avoids coupling tests to ureq's explicitly
unversioned connector API.

Minimum deterministic coverage before replacing `scripts/updater.sh`:

- HTTPS-only initial URL and HTTPS-to-HTTP downgrade rejection;
- redirect loop, sixth redirect, relative location, cross-host redirect, and stripped authorization;
- ambient proxy variables ignored;
- DNS/connect/header/body/global timeout classification;
- exact encoded limit, one-byte overflow, chunked body, absent/lying `Content-Length`;
- gzip and Brotli exact decoded limit, one-byte overflow, truncated stream, and decompression bomb;
- unknown/stacked encoding, bad status, oversized headers, and content-type policy;
- malformed UTF-8/base64/URI input, excessive nodes, long fields, and duplicate stable names;
- retrieval/parse/validation/persistence failure retaining the previous active snapshot;
- atomic publication, crash recovery, bounded predecessor retention, and digest verification;
- host loopback integration plus Android/WSA runtime smoke tests; final qualification still requires
  the roadmap's physical Android target.

## Rejected choices

**`minreq 3.0.0` with `https-rustls`: rejected.** It compiles and has a smaller core graph, but the
missing decompression, safe redirect policy, granular timing, first-layer body limit, and transport
substitution shift too much untrusted-network behavior into Flux. Its maintenance label and upstream
robustness warning strengthen that conclusion.

**`ureq` with `platform-verifier`: rejected for the standalone daemon.** It would better reflect
Android trust decisions, but only after adding a JVM-hosted application integration that the current
package does not possess.

**Native TLS/OpenSSL: rejected.** It adds platform/native build and certificate-discovery behavior
without solving the standalone Android trust-hosting decision. `vendored` would further expand
native build and provenance work.

**An async client: rejected for B1.** Periodic bounded downloads fit a blocking worker, and an async
runtime would add scheduling, dependency, memory, and shutdown surface without improving the
product contract.

## Sources

Local project sources:

- [L-UPDATER] [`scripts/updater.sh`](../../scripts/updater.sh)
- [L-SPEC] [Flux technical specification](../architecture/fluxd-technical-specification.md)

Pinned upstream and official sources:

- [U-CRATE] [`ureq 3.3.0` crates.io record](https://crates.io/api/v1/crates/ureq/3.3.0)
- [U-MANIFEST] [`ureq 3.3.0` manifest](https://github.com/algesten/ureq/blob/b2adbf00f9a7ac0e2fbcb39d23c1b4f3da723e5c/Cargo.toml)
- [U-LIB] [`ureq 3.3.0` crate documentation source](https://github.com/algesten/ureq/blob/b2adbf00f9a7ac0e2fbcb39d23c1b4f3da723e5c/src/lib.rs)
- [U-CONFIG] [`ureq 3.3.0` configuration](https://github.com/algesten/ureq/blob/b2adbf00f9a7ac0e2fbcb39d23c1b4f3da723e5c/src/config.rs)
- [U-RUN] [`ureq 3.3.0` request and redirect execution](https://github.com/algesten/ureq/blob/b2adbf00f9a7ac0e2fbcb39d23c1b4f3da723e5c/src/run.rs)
- [U-BODY] [`ureq 3.3.0` body limiter and decoder composition](https://github.com/algesten/ureq/blob/b2adbf00f9a7ac0e2fbcb39d23c1b4f3da723e5c/src/body/mod.rs)
- [U-PROXY] [`ureq 3.3.0` proxy environment handling](https://github.com/algesten/ureq/blob/b2adbf00f9a7ac0e2fbcb39d23c1b4f3da723e5c/src/proxy.rs)
- [U-AGENT] [`ureq 3.3.0` agent construction](https://github.com/algesten/ureq/blob/b2adbf00f9a7ac0e2fbcb39d23c1b4f3da723e5c/src/agent.rs)
- [M-CRATE] [`minreq 3.0.0` crates.io record](https://crates.io/api/v1/crates/minreq/3.0.0)
- [M-MANIFEST] [`minreq 3.0.0` manifest](https://github.com/neonmoe/minreq/blob/eb528443b54d1f38ff9b089bae2832f0753f7fe7/Cargo.toml)
- [M-LIB] [`minreq 3.0.0` crate documentation source](https://github.com/neonmoe/minreq/blob/eb528443b54d1f38ff9b089bae2832f0753f7fe7/src/lib.rs)
- [M-REQUEST] [`minreq 3.0.0` request, proxy, and redirect state](https://github.com/neonmoe/minreq/blob/eb528443b54d1f38ff9b089bae2832f0753f7fe7/src/request.rs)
- [M-CONNECTION] [`minreq 3.0.0` timeout and redirect execution](https://github.com/neonmoe/minreq/blob/eb528443b54d1f38ff9b089bae2832f0753f7fe7/src/connection.rs)
- [M-RESPONSE] [`minreq 3.0.0` eager and lazy response bodies](https://github.com/neonmoe/minreq/blob/eb528443b54d1f38ff9b089bae2832f0753f7fe7/src/response.rs)
- [RPV] [`rustls-platform-verifier 0.6.2` Android setup](https://github.com/1Password/rustls-platform-verifier/blob/1099f161bfc5e3ac7f90aad88b1bf788e72906cb/rustls-platform-verifier/README.md)
- [AWS-LC] [AWS-LC-RS platform support](https://aws.github.io/aws-lc-rs/platform_support.html)
- [RUST-ANDROID] [Rust Android platform support](https://doc.rust-lang.org/rustc/platform-support/android.html)
- [RS-0098] [`RUSTSEC-2026-0098`](https://github.com/RustSec/advisory-db/blob/29638ff054fdbb83d2844240f7ef7e576cb52629/crates/rustls-webpki/RUSTSEC-2026-0098.md)
- [RS-0099] [`RUSTSEC-2026-0099`](https://github.com/RustSec/advisory-db/blob/29638ff054fdbb83d2844240f7ef7e576cb52629/crates/rustls-webpki/RUSTSEC-2026-0099.md)
- [RS-0104] [`RUSTSEC-2026-0104`](https://github.com/RustSec/advisory-db/blob/29638ff054fdbb83d2844240f7ef7e576cb52629/crates/rustls-webpki/RUSTSEC-2026-0104.md)
