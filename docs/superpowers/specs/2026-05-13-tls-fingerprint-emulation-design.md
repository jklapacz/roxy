# TLS / HTTP/2 Fingerprint Emulation for Upstream Requests

**Status:** Design approved, awaiting plan
**Date:** 2026-05-13
**Scope:** v1 — single global default profile + optional per-request override, curated builtin profiles plus user-supplied custom profiles via TOML

## Goal

Allow roxy to emit upstream TLS ClientHellos and HTTP/2 SETTINGS frames that are byte-for-byte identical to a real browser (Chrome / Firefox / Safari / Edge), so origins protected by JA3 / JA4 / Akamai fingerprint checks do not block roxy-routed traffic.

The feature operates on the **upstream** side only: roxy's existing client-facing TLS termination (rustls + CA-minted leaf cert) is unchanged. Clients connect to roxy via plaintext CONNECT exactly as today.

## Non-goals

- Fingerprint capture utility (Wireshark → TOML pipeline). Deferred to a follow-up project.
- HTTP/3 / QUIC fingerprinting. wreq supports it; deferred until there is demand.
- IP / TCP layer fingerprinting (p0f-class signals). Out of roxy's control.
- Per-host rotation across a profile pool. Re-evaluate after v1 ships.
- Automatic header-order rewriting. v1 trusts clients to supply headers in the order matching the chosen profile; this is documented as a requirement.
- Defeating any specific anti-bot product. Fidelity is wreq's contract; we ship roxy as the integration layer.

## Architecture

Two layers of new code.

### New crate: `roxy-impersonate`

Wraps [`wreq`](https://docs.rs/wreq) + [`wreq_util`](https://docs.rs/wreq-util) and owns the profile abstraction.

```
crates/roxy-impersonate/
  src/
    lib.rs        ImpersonateClient, public re-exports
    profile.rs    Profile enum, name parsing/canonicalization, builtin registry
    custom.rs     TOML profile loader (Path B custom profiles)
    body.rs       ImpersonateBody adapter (wreq Response stream → http_body::Body)
  profiles/       Directory exists for user-supplied custom profile .toml files.
                  Builtin profiles are compile-time enum, not files.
```

`ImpersonateClient` holds a registry of profile-name → pre-built `wreq::Client`. Clients are built lazily on first use of a profile and cached for the process lifetime. Each `wreq::Client` is configured with one `Emulation` (or one `EmulationProvider` for custom profiles) at construction; per-request override is not supported by wreq, so the per-profile client model is required.

### Trait + body unification in `roxy-http`

```rust
// crates/roxy-http/src/upstream.rs

pub enum UpstreamBody {
    Hyper(hyper::body::Incoming),
    Impersonate(roxy_impersonate::ImpersonateBody),
}

impl http_body::Body for UpstreamBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;
    fn poll_frame(...) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> { ... }
}

#[async_trait]
pub trait Upstream: Send + Sync {
    async fn send(
        &self,
        profile: ProfileLabel,
        req: Request<ClientBody>,
    ) -> Result<Response<UpstreamBody>, UpstreamError>;
}
```

The existing `UpstreamClient` (hyper + rustls) implements `Upstream`, ignoring `profile` (it is only invoked for the `_default` label). The new `ImpersonateClient` also implements `Upstream`, dispatching by profile.

### Router in `roxy-http`

```rust
// crates/roxy-http/src/router.rs (new)

pub struct UpstreamRouter {
    rustls: UpstreamClient,
    impersonate: Option<roxy_impersonate::ImpersonateClient>,
    default_profile: Option<String>,
}
```

`UpstreamRouter::send` reads the resolved profile label, dispatches to `impersonate` if the label names a known profile, otherwise to `rustls` (the `_default` label or `none` override).

### Handler integration

`roxy-proxy::handler` gains a small step before the cache-key computation:

1. Read `X-Roxy-Fingerprint` header; resolve to a `ProfileLabel` (string).
2. Strip the header from `req` if config says so (default true).
3. Compute `CacheKey::from_parts(&label, method, scheme, host, path, query)`.
4. Cache lookup as today.
5. On miss, call `router.send(label, upstream_req)`.
6. `tee_pump` over the returned `UpstreamBody` (signature becomes generic over `B: http_body::Body<Data=Bytes, Error=io::Error> + Unpin`).

## Configuration

### TOML schema (extension to `roxy-config`)

```toml
[impersonate]
# Optional. If set, every upstream request without an explicit override uses this profile.
# Absent => unfingerprinted (existing rustls path).
default_profile = "chrome-137"

# Optional. Directory of *.toml custom profile specs.
# Defaults to ./profiles relative to the config file.
profiles_dir = "./profiles"

# Optional. Strip the X-Roxy-Fingerprint header from the upstream request. Default true.
strip_header = true
```

### CLI

`roxy serve --fingerprint <name>` overrides `default_profile` from config. No other flags introduced.

### Per-request header

Single header: `X-Roxy-Fingerprint: <profile-name>`.

| Header state                       | Behavior                                          |
|------------------------------------|---------------------------------------------------|
| Absent                             | Use `default_profile` (or rustls if none)         |
| Empty value                        | Same as absent                                    |
| Known profile name                 | Use that profile                                  |
| `none`                             | Force rustls path (escape hatch for the default)  |
| Unknown profile name               | 502 — `roxy: unknown fingerprint <name>`          |
| Set more than once                 | 400 — `roxy: X-Roxy-Fingerprint must be set at most once` |
| Contains non-`[a-z0-9-]` chars     | 400 — body includes the validation regex          |

The header is stripped from `req` before forwarding when `strip_header = true`.

### Profile names

Validation regex: `^[a-z0-9][a-z0-9-]*$`.

Two sources merged at startup:

1. **Builtins** — kebab-case names from `wreq_util::Emulation`:
   - `chrome-137` → `Emulation::Chrome137`
   - `firefox-139` → `Emulation::Firefox139`
   - `safari-18-3-1` → `Emulation::Safari18_3_1`
   - `edge-134` → `Emulation::Edge134`
   - `okhttp-5` → `Emulation::OkHttp5`
   - (Initial shipping set; adding a new wreq variant is a one-line change in `profile.rs`.)
2. **Custom** — every `*.toml` under `profiles_dir`, registered under its declared `name` field.

On name collision, the builtin wins and a warning is logged at startup.

Reserved label: `_default` (used internally as the cache-key component for the rustls path; the leading underscore cannot appear in user profile names due to the validation regex).

### Custom profile TOML schema (Path B)

The mechanism that lets users add fingerprints wreq does not yet ship presets for (e.g. a new Chrome version).

```toml
name = "chrome-148"

[tls]
alpn = ["h2", "http/1.1"]
cipher_suites = [
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_256_GCM_SHA384",
  # ... ordered
]
extensions = [
  "server_name",
  "extended_master_secret",
  "renegotiation_info",
  "supported_groups",
  # ... ordered
]
supported_versions = ["TLS1.3", "TLS1.2"]
signature_algorithms = [
  "ecdsa_secp256r1_sha256",
  # ...
]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_frame_size = 16384
max_header_list_size = 262144
settings_order = [
  "HEADER_TABLE_SIZE",
  "ENABLE_PUSH",
  "INITIAL_WINDOW_SIZE",
  "MAX_FRAME_SIZE",
  "MAX_HEADER_LIST_SIZE",
]
header_order = [":method", ":authority", ":scheme", ":path", "user-agent"]
```

`roxy-impersonate::custom` loads this into a `wreq::tls::TlsConfig` + `wreq::Http2Config` and assembles a `wreq::EmulationProvider`. The struct implements `wreq::EmulationProviderFactory` so it plugs into `ClientBuilder::emulation(...)` exactly like a builtin.

When wreq eventually ships `Emulation::Chrome148`, the user collapses the custom profile into a builtin enum entry — a single-line `profile.rs` change.

## Data flow

### Cache hit (fingerprint affects key only)

1. Resolve profile label from `X-Roxy-Fingerprint` or default.
2. `CacheKey::from_parts(label, method, ...)`.
3. Cache hit → stream cached body. No upstream call. No wreq involvement.

### Cache miss, fingerprinted

1. As above; cache misses.
2. `UpstreamRouter::send(label, req)` → `ImpersonateClient::send(label, req)`.
3. `ImpersonateClient` looks up (or lazily builds) the `wreq::Client` for that label.
4. wreq performs TLS handshake with the profile's ClientHello and HTTP/2 SETTINGS.
5. wreq returns a `Response`; we wrap it in `ImpersonateBody` and re-emit as `UpstreamBody::Impersonate(...)`.
6. Existing `tee_pump` consumes it identically to the rustls path: one branch to the client, one to `FsCache::begin_store`.

### Cache miss, unfingerprinted

`UpstreamRouter` routes to the existing rustls `UpstreamClient`. Body returns as `UpstreamBody::Hyper(Incoming)`. All downstream logic is bit-identical to current behavior.

## Cache key change (breaking)

```rust
// crates/roxy-cache/src/key.rs

pub fn from_parts(
    profile: &str,        // "_default" for rustls path, else the resolved profile label
    method: &str,
    scheme: &str,
    host: &str,
    path: &str,
    query: Option<&str>,
) -> Self
```

Pre-existing cache entries are invalidated. Pre-1.0; no migration shim. Documented in README under cache section.

## Error handling

### Startup failures (process refuses to start)

- `default_profile = "<unknown>"` → exit with available-profiles list
- Malformed `.toml` under `profiles_dir` → exit, naming the file and parse error
- Custom profile rejected by wreq (invalid extension name, unknown cipher, etc.) → exit, naming the profile and wreq's error
- Custom profile name fails regex `^[a-z0-9][a-z0-9-]*$` → exit
- Custom profile name collides with a builtin → log warning, builtin wins, continue

### Request-time failures

`UpstreamError` gains:

```rust
#[error("unknown fingerprint: {0}")]
UnknownFingerprint(String),

#[error("impersonate client: {0}")]
Impersonate(#[from] wreq::Error),
```

Handler mapping. Client-facing bodies are generic; categorization lives in logs.

| Source                                    | HTTP response                              | Log     | Log fields                                        |
|-------------------------------------------|--------------------------------------------|---------|---------------------------------------------------|
| `UnknownFingerprint`                      | 502 `roxy: unknown fingerprint`            | warn    | `profile=<label>` `host=<authority>`              |
| `Impersonate` — TLS handshake             | 502 `roxy: upstream error`                 | warn    | `profile=<label>` `host=<authority>` `kind=tls`   |
| `Impersonate` — connect timeout           | 502 `roxy: upstream error`                 | warn    | `profile=<label>` `host=<authority>` `kind=timeout` |
| `Impersonate` — h2 stream / protocol      | 502 `roxy: upstream error`                 | warn    | `profile=<label>` `host=<authority>` `kind=h2`    |
| `Client` (existing rustls path)           | 502 `roxy: upstream error`                 | warn    | `host=<authority>`                                |

`UnknownFingerprint` is the one exception that gets a distinct response body: it is a client-side configuration error (the caller asked for a profile that does not exist), so the client needs to know that specifically. Every other case is an upstream-state problem that the client can correlate via request ID.

### 5xx pass-through and disconnect cap

Unchanged from today. Origin 5xx responses are forwarded but not cached. `tee_pump`'s disconnect cap drains upstream up to the cap after client disconnect so cache finalization can complete. These behaviors are body-source-agnostic by design.

## Dependency / build implications

- New deps: `wreq` (with `stream` feature), `wreq_util`. Transitive: `boring2`, `tokio-boring2`, BoringSSL build.
- Build prerequisites added: `cmake`, `perl`, `clang`. Document in README.
- Approximate cost: +30–60s clean compile, +5–10MB final binary.
- Constraint: do not introduce any transitive dep on `openssl-sys`. wreq's BoringSSL symbol-conflicts with it without the `prefix-symbols` feature. roxy today uses `ring` + `rustls`, no openssl-sys; preserve this. If a future dep change pulls openssl-sys, enable wreq's `prefix-symbols` feature.
- Feature flagging the impersonation capability is explicitly rejected: it is the headline feature, gating it would confuse users.

## Testing strategy

### Ring 1 — Unit tests (no network)

In `roxy-cache`:
- Cache key partitions by profile (two `from_parts` calls with same method/host/path but different profile labels produce different keys).

In `roxy-impersonate`:
- Profile name canonicalization: wreq's PascalCase ↔ our kebab-case.
- Builtin registry is complete (every `Profile` enum variant has a name).
- TOML loader: well-formed parses, missing required sections fail with field name, unknown extension fails with offending field.
- Registry collision warning logged when a custom profile collides with a builtin; builtin wins.

In `roxy-proxy`:
- Header resolution table: absent, present-known, present-`none`, present-unknown, multiple, malformed.
- Header stripped from upstream request when `strip_header = true`.

### Ring 2 — Integration tests (fast, fake-origin fixture)

Build on the existing harness from commit `9ccc306`. Fake origin does not validate TLS fingerprints, so these tests verify routing and caching, not byte fidelity.

- `impersonate_path_miss_then_hit`: configure `default_profile`, miss then hit, response identical.
- `profile_partition_in_cache`: same URL with two profiles produces two cache entries.
- `none_opts_out_of_default`: default configured, `X-Roxy-Fingerprint: none` takes the rustls path (verify which client received the call).
- `unknown_profile_502`: `X-Roxy-Fingerprint: chrome-999` → 502, no upstream call made.
- `5xx_pass_through_impersonate`: fake origin returns 503; forwarded to client; no cache write.
- `custom_profile_loads_and_serves`: tmpdir `profiles_dir` with a minimal valid `test.toml`, full request round-trip succeeds. Validates Path B end-to-end without testing fingerprint bytes.

### Ring 3 — Fingerprint fidelity smoke (`#[ignore]`, network-required)

Following the precedent of commit `69b4471`. Operator-run, not in CI.

- `fingerprint_smoke_chrome137`: roxy → `https://tls.peet.ws/api/all` (or equivalent JA4/Akamai echo), parse JSON, assert observed `ja4` and `akamai_fingerprint` match Chrome 137 known-good values. One test per shipped builtin profile.
- `fingerprint_smoke_custom`: same, against a custom profile loaded from TOML. Proves the Path B pipeline emits the bytes configured.

### Explicit non-test

We do not assert that wreq's bytes match real Chrome. That is wreq's responsibility, validated by their test suite. Ring 3 is a release-gate sanity check, not a fidelity audit.

## Sequencing for implementation

Ordered foundation-up; each step independently testable.

1. `CacheKey::from_parts` adds profile component; existing tests updated to pass `_default`.
2. `UpstreamBody` enum + `trait Upstream` in `roxy-http`; rustls `UpstreamClient` implements the trait; `tee_pump` made generic. No behavior change — pure rotation.
3. `roxy-impersonate` crate: `Profile` enum, builtin registry, `ImpersonateClient`, `ImpersonateBody` adapter.
4. Custom TOML profile loader (`roxy-impersonate::custom`).
5. `UpstreamRouter` in `roxy-http`; handler wired through it.
6. CLI `--fingerprint` flag + `[impersonate]` parsing in `roxy-config`.
7. Ring 1 + Ring 2 tests alongside steps 3–6.
8. Ring 3 smoke tests at the end as a fidelity gate.

Each becomes a beads issue under one tracking epic. The implementation-plan skill will expand them with acceptance criteria.

## Pre-merge gates

- All Ring 1 + Ring 2 tests pass under `cargo test`.
- Ring 3 smoke passes against `tls.peet.ws/api/all` (or equivalent) for at least one shipped builtin profile.
- `cargo build --release` succeeds on macOS + Linux.
- Existing integration tests in `roxy-proxy/tests/` pass with no `[impersonate]` section configured — regression guard for the zero-overhead-when-absent contract.

## Open questions for future iterations

- When wreq ships `EmulationProvider` for per-request overrides on a single `Client`, revisit the per-profile client-pool model — it may collapse to a single `Client` with much simpler resource accounting.
- Whether to ship pre-baked custom profiles for Chrome/Firefox versions newer than wreq's enum, owned by roxy. Today's stance: no, custom profiles live in user repos. Reconsider if many users land on the same ones.
- Header-order auto-rewriting: today clients must supply headers in browser-matching order for the Akamai fingerprint to be intact. If real users routinely get this wrong, we may add a "header reorder" toggle in the profile.
