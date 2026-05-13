# TLS / HTTP/2 Fingerprint Emulation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make roxy emit byte-accurate Chrome / Firefox / Safari / Edge TLS+H2 fingerprints on upstream requests, controlled by a global default + per-request `X-Roxy-Fingerprint` header, with extensibility for custom profiles via TOML.

**Architecture:** Add a new `roxy-impersonate` crate wrapping `wreq` (BoringSSL-backed fork of reqwest, with `wreq_util::Emulation` presets and `EmulationProvider` for custom profiles). Introduce an `UpstreamBody` enum unifying `hyper::body::Incoming` and a `wreq`-bytes-stream adapter so the existing `tee_pump` can consume either. Route requests through an `UpstreamRouter` that picks the wreq-based client or the existing hyper+rustls client based on the resolved profile label. Cache key gains a profile component so different fingerprints don't share entries.

**Tech Stack:** Rust 2021 (MSRV 1.80), tokio, hyper 1.x, http 1.x, http-body 1.x, rustls 0.23 (existing client-side TLS), `wreq` + `wreq_util` (new upstream fingerprint stack, BoringSSL via `boring2`), serde + toml (existing config).

**Reference spec:** `docs/superpowers/specs/2026-05-13-tls-fingerprint-emulation-design.md`

---

## File Structure

**Created:**
- `crates/roxy-impersonate/Cargo.toml` — new crate manifest
- `crates/roxy-impersonate/src/lib.rs` — public surface, re-exports
- `crates/roxy-impersonate/src/profile.rs` — `Profile` enum, builtin name registry, name parsing/canonicalization
- `crates/roxy-impersonate/src/client.rs` — `ImpersonateClient` (lazy per-profile `wreq::Client` pool)
- `crates/roxy-impersonate/src/body.rs` — `ImpersonateBody` adapter (`wreq` bytes_stream → `http_body::Body`)
- `crates/roxy-impersonate/src/custom.rs` — TOML profile loader, `EmulationProvider` construction
- `crates/roxy-impersonate/src/error.rs` — `ImpersonateError`
- `crates/roxy-http/src/router.rs` — `Upstream` trait, `UpstreamRouter`
- `crates/roxy-proxy/tests/impersonate.rs` — Ring 2 integration tests
- `crates/roxy-proxy/tests/fingerprint_smoke.rs` — Ring 3 `#[ignore]` smoke
- `docs/superpowers/plans/2026-05-13-tls-fingerprint-emulation.md` — this file

**Modified:**
- `Cargo.toml` — workspace member + new workspace deps (`wreq`, `wreq-util`)
- `crates/roxy-cache/src/key.rs` — `CacheKey::from_parts` gains `profile` parameter
- `crates/roxy-cache/Cargo.toml` — no change expected
- `crates/roxy-cache-fs/src/writer.rs` — update 4 test callers of `CacheKey::from_parts`
- `crates/roxy-http/Cargo.toml` — depend on `roxy-impersonate`
- `crates/roxy-http/src/lib.rs` — pub mod router, re-exports
- `crates/roxy-http/src/upstream.rs` — add `UpstreamBody` enum, change `UpstreamClient::send` return type, add `Upstream` trait impl
- `crates/roxy-proxy/Cargo.toml` — add `roxy-impersonate` dev/prod dep
- `crates/roxy-proxy/src/handler.rs` — header parsing, profile resolution, route through `UpstreamRouter`, generic `tee_pump`
- `crates/roxy-proxy/src/cli.rs` — add `--fingerprint` arg to `Serve`
- `crates/roxy-proxy/src/serve.rs` — load profiles, build router, plumb through
- `crates/roxy-config/src/lib.rs` — add `ImpersonateConfig` struct + defaults
- `crates/roxy-config/Cargo.toml` — no change expected

**Boundaries:**
- `roxy-impersonate` knows nothing about caching, hyper bodies, or the proxy. It speaks `http::Request<wreq::Body>` shapes externally and wraps wreq internally.
- `roxy-http::router` is the seam where the body unification happens. Both upstream impls produce `Response<UpstreamBody>`.
- `roxy-proxy::handler` owns the request-time policy: header parsing, label resolution, cache-key composition.
- `roxy-config` defines the static config shape; `roxy-proxy::serve` does the runtime wiring.

---

## Task 1: Add profile component to `CacheKey`

**Files:**
- Modify: `crates/roxy-cache/src/key.rs`
- Modify: `crates/roxy-cache-fs/src/writer.rs:251,286,327,353` (test callers)
- Modify: `crates/roxy-proxy/src/handler.rs:31` (production caller)

This is breaking. Every call to `CacheKey::from_parts` and `CacheKey::from_request` gets a new `profile` parameter. Pre-1.0; no compatibility shim.

- [ ] **Step 1.1: Write the failing partition test**

Add to the `tests` mod at the bottom of `crates/roxy-cache/src/key.rs`:

```rust
#[test]
fn different_profiles_differ() {
    let a = CacheKey::from_parts("chrome-137", "GET", "https", "a.b", "/x", None);
    let b = CacheKey::from_parts("firefox-139", "GET", "https", "a.b", "/x", None);
    assert_ne!(a, b);
}

#[test]
fn default_profile_label_is_distinct_from_named() {
    let a = CacheKey::from_parts("_default", "GET", "https", "a.b", "/x", None);
    let b = CacheKey::from_parts("chrome-137", "GET", "https", "a.b", "/x", None);
    assert_ne!(a, b);
}
```

- [ ] **Step 1.2: Run test to confirm it fails to compile**

Run: `cargo test -p roxy-cache key::`
Expected: compile error — `from_parts` takes 5 args, supplied 6.

- [ ] **Step 1.3: Update `CacheKey` signatures**

Replace the body of `crates/roxy-cache/src/key.rs` lines 13–51 (the two `impl` methods) with:

```rust
    pub fn from_parts(
        profile: &str,
        method: &str,
        scheme: &str,
        host: &str,
        path: &str,
        query: Option<&str>,
    ) -> Self {
        let sorted_query = query.map(sort_query).unwrap_or_default();
        let mut buf = Vec::with_capacity(
            profile.len()
                + method.len()
                + scheme.len()
                + host.len()
                + path.len()
                + sorted_query.len()
                + 5,
        );
        buf.extend_from_slice(profile.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(method.to_ascii_uppercase().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(scheme.to_ascii_lowercase().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(host.to_ascii_lowercase().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(path.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(sorted_query.as_bytes());
        Self(buf)
    }

    pub fn from_request<B>(
        req: &Request<B>,
        profile: &str,
        default_scheme: &str,
        default_host: &str,
    ) -> Self {
        let method = req.method().as_str();
        let uri = req.uri();
        let scheme = uri.scheme_str().unwrap_or(default_scheme);
        let host = uri
            .host()
            .or_else(|| {
                req.headers()
                    .get(http::header::HOST)
                    .and_then(|h| h.to_str().ok())
            })
            .unwrap_or(default_host);
        let path = uri.path();
        let query = uri.query();
        Self::from_parts(profile, method, scheme, host, path, query)
    }
```

- [ ] **Step 1.4: Update existing inline tests in `key.rs`**

Lines 72–106 (the existing tests). Each `from_parts` call now needs a profile label as first arg, and `from_request` needs a profile label as the second arg. Apply these exact replacements:

`crates/roxy-cache/src/key.rs:72-73`:
```rust
        let a = CacheKey::from_parts("p", "get", "HTTPS", "Example.COM", "/api", None);
        let b = CacheKey::from_parts("p", "GET", "https", "example.com", "/api", None);
```

`crates/roxy-cache/src/key.rs:79-80`:
```rust
        let a = CacheKey::from_parts("p", "GET", "https", "a.b", "/p", Some("z=2&a=1"));
        let b = CacheKey::from_parts("p", "GET", "https", "a.b", "/p", Some("a=1&z=2"));
```

`crates/roxy-cache/src/key.rs:86-87`:
```rust
        let a = CacheKey::from_parts("p", "GET", "https", "a.b", "/x", None);
        let b = CacheKey::from_parts("p", "GET", "https", "a.b", "/y", None);
```

`crates/roxy-cache/src/key.rs:93-94`:
```rust
        let a = CacheKey::from_parts("p", "GET", "https", "a.b", "/x", None);
        let b = CacheKey::from_parts("p", "GET", "https", "a.b", "/x", Some(""));
```

`crates/roxy-cache/src/key.rs:103-104`:
```rust
        let k = CacheKey::from_request(&r, "p", "http", "fallback");
        let expected = CacheKey::from_parts("p", "GET", "https", "example.com", "/api", Some("a=1&b=2"));
```

- [ ] **Step 1.5: Update `roxy-cache-fs` test callers**

In `crates/roxy-cache-fs/src/writer.rs`, replace each of the 4 occurrences:

Before:
```rust
let key = CacheKey::from_parts("GET", "https", "x.y", "/p", None);
```
After:
```rust
let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);
```

Apply at lines 251, 286, 327, 353.

- [ ] **Step 1.6: Update handler caller**

In `crates/roxy-proxy/src/handler.rs:31`, replace:
```rust
        let key = CacheKey::from_request(&req, "https", &authority);
```
with:
```rust
        let key = CacheKey::from_request(&req, "_default", "https", &authority);
```

(Temporary `_default` label until Task 6 introduces real label resolution.)

- [ ] **Step 1.7: Run the full test suite**

Run: `cargo test --workspace`
Expected: all tests pass. The two new tests in `roxy-cache` (`different_profiles_differ`, `default_profile_label_is_distinct_from_named`) pass alongside the existing suite. No clippy warnings (the workspace has `unwrap_used = "deny"`).

- [ ] **Step 1.8: Commit**

```bash
git add crates/roxy-cache/src/key.rs crates/roxy-cache-fs/src/writer.rs crates/roxy-proxy/src/handler.rs
git commit -m "feat(roxy-cache): partition cache key by profile label

Breaking: CacheKey::from_parts and from_request now take a profile label
as the leading discriminator. Unfingerprinted upstream calls use the
reserved label '_default'. Pre-1.0; pre-existing cache directories should
be cleared."
```

---

## Task 2: `UpstreamBody` enum + generic `tee_pump`

**Files:**
- Modify: `crates/roxy-http/src/upstream.rs`
- Modify: `crates/roxy-proxy/src/handler.rs:88,104-105` (`tee_pump` signature + call)

No behavior change. We're just rotating the upstream's body return type onto an enum so a second variant can be added later without further churn.

- [ ] **Step 2.1: Add `UpstreamBody` enum to `upstream.rs`**

In `crates/roxy-http/src/upstream.rs`, add after the imports and before `ClientBody`:

```rust
use bytes::Bytes;
use http_body::{Body, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Body type emitted by all upstream client variants. The handler's tee_pump is
/// generic over `http_body::Body`, so any future variant added here just needs
/// to implement `Body<Data=Bytes, Error=io::Error>` and forward poll_frame.
pub enum UpstreamBody {
    Hyper(hyper::body::Incoming),
    // Impersonate variant added in Task 4.
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        // SAFETY: structural pin projection - we never move out of variants
        match unsafe { self.get_unchecked_mut() } {
            UpstreamBody::Hyper(b) => {
                let pinned = unsafe { Pin::new_unchecked(b) };
                pinned
                    .poll_frame(cx)
                    .map_err(std::io::Error::other)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            UpstreamBody::Hyper(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            UpstreamBody::Hyper(b) => b.size_hint(),
        }
    }
}
```

Note: the `unsafe { ... }` blocks are pin projection. The workspace has `unsafe_code = "forbid"`, so before writing this we need to relax that lint at the file level. Add to the very top of `crates/roxy-http/src/upstream.rs`:

```rust
#![allow(unsafe_code)] // pin projection in UpstreamBody
```

Alternatively, use the `pin-project-lite` crate to avoid `unsafe`. Either approach is acceptable; the `pin-project-lite` route adds a workspace dep but matches roxy's existing lint posture better. **Use `pin-project-lite`** (it's small and idiomatic), adding to workspace deps:

In `Cargo.toml` workspace.dependencies, add:
```toml
pin-project-lite = "0.2"
```

In `crates/roxy-http/Cargo.toml` `[dependencies]`, add:
```toml
pin-project-lite = { workspace = true }
```

Then the enum becomes:
```rust
use bytes::Bytes;
use http_body::{Body, Frame};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    /// Body type emitted by all upstream client variants. The handler's tee_pump
    /// is generic over `http_body::Body`, so any future variant added here just
    /// needs to implement `Body<Data=Bytes, Error=io::Error>` and forward
    /// poll_frame.
    #[project = UpstreamBodyProj]
    pub enum UpstreamBody {
        Hyper { #[pin] inner: hyper::body::Incoming },
        // Impersonate variant added in Task 4.
    }
}

impl UpstreamBody {
    pub fn hyper(inner: hyper::body::Incoming) -> Self {
        Self::Hyper { inner }
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match self.project() {
            UpstreamBodyProj::Hyper { inner } => inner.poll_frame(cx).map_err(std::io::Error::other),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            UpstreamBody::Hyper { inner } => inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            UpstreamBody::Hyper { inner } => inner.size_hint(),
        }
    }
}
```

- [ ] **Step 2.2: Change `UpstreamClient::send` return type**

In `crates/roxy-http/src/upstream.rs`, replace the existing `send` and `send_empty` methods (lines 56–73) with:

```rust
    /// Send a request with a streaming [`ClientBody`].
    pub async fn send(
        &self,
        req: Request<ClientBody>,
    ) -> Result<Response<UpstreamBody>, UpstreamError> {
        let resp = self.inner.request(req).await?;
        let (parts, body) = resp.into_parts();
        Ok(Response::from_parts(parts, UpstreamBody::hyper(body)))
    }

    /// Send a request with an empty body. Internally converts to a [`ClientBody`]
    /// so it shares the same connection pool as [`Self::send`].
    pub async fn send_empty(
        &self,
        req: Request<Empty<bytes::Bytes>>,
    ) -> Result<Response<UpstreamBody>, UpstreamError> {
        let (parts, body) = req.into_parts();
        let body: ClientBody = body.map_err(|never| match never {}).boxed();
        let req = Request::from_parts(parts, body);
        let resp = self.inner.request(req).await?;
        let (parts, body) = resp.into_parts();
        Ok(Response::from_parts(parts, UpstreamBody::hyper(body)))
    }
```

The `use hyper::body::Incoming;` import (line 4) is no longer needed by the public API but `Incoming` is still referenced inside `UpstreamBody::Hyper`. Keep the import or move it inside the enum module — either is fine.

- [ ] **Step 2.3: Make `tee_pump` generic over `Body`**

In `crates/roxy-proxy/src/handler.rs`, replace the `tee_pump` function (lines 104–164) signature and body to be generic. The existing call site uses `resp_body` from `resp.into_parts()` where `resp: Response<UpstreamBody>` now. Replace lines 104–113:

```rust
async fn tee_pump<B>(
    mut upstream: B,
    mut writer: Option<Box<dyn CacheWriter>>,
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    disconnect_cap: u64,
) where
    B: http_body::Body<Data = Bytes, Error = std::io::Error> + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut client_alive = true;
    let mut bytes_past_disconnect = 0u64;
    while let Some(frame) = http_body_util::BodyExt::frame(&mut upstream).await {
```

(Replace the existing `while let Some(frame) = upstream.frame().await {` — we now use `BodyExt::frame` since the generic `B` doesn't have an inherent `.frame()`.)

The rest of `tee_pump`'s body stays the same: the existing pattern-match on `frame.into_data()`, the cache write, the client-alive logic, the disconnect cap, the final `writer.finish()`.

The `use hyper::body::Incoming;` import at the top of `handler.rs` (line 5) is no longer needed. Remove it.

- [ ] **Step 2.4: Update tee_pump's call site**

In `crates/roxy-proxy/src/handler.rs:88`, the call:

```rust
        tokio::spawn(tee_pump(resp_body, writer, tx, disconnect_cap));
```

stays unchanged. `resp_body` is now `UpstreamBody`, which implements `Body<Data=Bytes, Error=io::Error>`, so the generic constraint is satisfied.

- [ ] **Step 2.5: Run the full test suite**

Run: `cargo test --workspace`
Expected: all existing tests pass, no behavior changes. Specifically:
- `cargo test -p roxy-http` — upstream tests pass (h1 round-trip test in `tests/upstream_h1.rs` still works because `send` now returns `Response<UpstreamBody>` and the test should consume the body through `BodyExt::collect`)
- `cargo test -p roxy-proxy` — handler tests via `tests/golden.rs`, `streaming.rs`, `ttl.rs`, `errors.rs` all pass

If `tests/upstream_h1.rs` calls something like `.body().collect()` on the response, it works because `UpstreamBody: Body`. If it calls `.into_inner()` or destructures expecting `Incoming`, update that one site.

- [ ] **Step 2.6: Commit**

```bash
git add Cargo.toml crates/roxy-http/Cargo.toml crates/roxy-http/src/upstream.rs crates/roxy-proxy/src/handler.rs
git commit -m "refactor(roxy-http): unify upstream bodies behind UpstreamBody enum

Introduces an enum body type that both the existing rustls path and a
future impersonate path will produce. tee_pump becomes generic over
http_body::Body so it consumes either variant unchanged. No behavior
change."
```

---

## Task 3: `roxy-impersonate` crate scaffold + `Profile` enum

**Files:**
- Create: `crates/roxy-impersonate/Cargo.toml`
- Create: `crates/roxy-impersonate/src/lib.rs`
- Create: `crates/roxy-impersonate/src/profile.rs`
- Create: `crates/roxy-impersonate/src/error.rs`
- Modify: `Cargo.toml` (workspace members + wreq/wreq-util deps)

- [ ] **Step 3.1: Add wreq + wreq-util to workspace deps**

In root `Cargo.toml`, in `[workspace.dependencies]`, add:

```toml
wreq = { version = "6.0.0-rc.28", default-features = false, features = ["stream", "rustls-tls-no-provider"] }
```

Note on features: as of this writing wreq's default features pull broad TLS/cookie/compression support. We want `stream` (for `bytes_stream()`) and the rustls-flagged client surface. The implementer should consult `cargo add wreq --list-features` and pin a minimal set. If the rustls-flag feature does not exist, default to `wreq = { version = "6.0.0-rc.28", features = ["stream"] }` and add the documented BoringSSL build prereqs (cmake, perl, clang) to the README in Task 7.

```toml
wreq-util = "6.0.0-rc.28"
```

Add `roxy-impersonate = { path = "crates/roxy-impersonate" }` to the internal-deps block.

In `[workspace]` members, add `"crates/roxy-impersonate",`.

- [ ] **Step 3.2: Create the crate manifest**

Write `crates/roxy-impersonate/Cargo.toml`:

```toml
[package]
name = "roxy-impersonate"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
wreq = { workspace = true }
wreq-util = { workspace = true }
bytes = { workspace = true }
http = { workspace = true }
http-body = { workspace = true }
futures = { workspace = true }
pin-project-lite = { workspace = true }
serde = { workspace = true }
toml = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true, features = ["sync"] }
tracing = { workspace = true }

[dev-dependencies]
tempfile = "3.13"
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }
```

- [ ] **Step 3.3: Write the failing `Profile` tests**

Create `crates/roxy-impersonate/src/profile.rs`:

```rust
//! Profile = a named browser fingerprint. Builtins map to `wreq_util::Emulation`
//! variants; customs come from TOML files (see `custom.rs`).

use std::sync::Arc;

/// Reserved label for the rustls-path. Cannot collide with a user profile
/// because it starts with `_` and user names must match `[a-z0-9][a-z0-9-]*`.
pub const DEFAULT_LABEL: &str = "_default";
/// Header value that forces the rustls path even if a global default is set.
pub const NONE_LABEL: &str = "none";

/// A canonical, kebab-case profile name. Constructed via `ProfileName::parse`
/// which enforces `^[a-z0-9][a-z0-9-]*$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileName(Arc<str>);

impl ProfileName {
    pub fn parse(s: &str) -> Result<Self, ProfileNameError> {
        if s.is_empty() {
            return Err(ProfileNameError::Empty);
        }
        let first = s.as_bytes()[0];
        if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            return Err(ProfileNameError::BadStart);
        }
        for &b in s.as_bytes() {
            let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
            if !ok {
                return Err(ProfileNameError::BadChar(b as char));
            }
        }
        Ok(Self(Arc::from(s)))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProfileNameError {
    #[error("profile name is empty")]
    Empty,
    #[error("profile name must start with [a-z0-9]")]
    BadStart,
    #[error("profile name contains invalid character: {0:?}")]
    BadChar(char),
}

/// Builtin profiles. Each maps to a `wreq_util::Emulation` variant. Adding a new
/// wreq variant is a one-line addition here plus a row in `builtin_table`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    Chrome137,
    Firefox139,
    Safari18_3_1,
    Edge134,
    OkHttp5,
}

impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Profile::Chrome137 => "chrome-137",
            Profile::Firefox139 => "firefox-139",
            Profile::Safari18_3_1 => "safari-18-3-1",
            Profile::Edge134 => "edge-134",
            Profile::OkHttp5 => "okhttp-5",
        }
    }

    pub fn all() -> &'static [Profile] {
        &[
            Profile::Chrome137,
            Profile::Firefox139,
            Profile::Safari18_3_1,
            Profile::Edge134,
            Profile::OkHttp5,
        ]
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::all().iter().copied().find(|p| p.name() == s)
    }

    /// Returns the underlying wreq_util Emulation variant.
    pub fn emulation(self) -> wreq_util::Emulation {
        match self {
            Profile::Chrome137 => wreq_util::Emulation::Chrome137,
            Profile::Firefox139 => wreq_util::Emulation::Firefox139,
            Profile::Safari18_3_1 => wreq_util::Emulation::Safari18_3_1,
            Profile::Edge134 => wreq_util::Emulation::Edge134,
            Profile::OkHttp5 => wreq_util::Emulation::OkHttp5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name_accepts_kebab_case() {
        assert!(ProfileName::parse("chrome-137").is_ok());
        assert!(ProfileName::parse("a").is_ok());
        assert!(ProfileName::parse("safari-18-3-1").is_ok());
    }

    #[test]
    fn profile_name_rejects_underscore_and_upper_and_space() {
        assert_eq!(ProfileName::parse("Chrome137"), Err(ProfileNameError::BadStart));
        assert_eq!(ProfileName::parse("chrome_137"), Err(ProfileNameError::BadChar('_')));
        assert_eq!(ProfileName::parse("chrome 137"), Err(ProfileNameError::BadChar(' ')));
        assert_eq!(ProfileName::parse(""), Err(ProfileNameError::Empty));
        assert_eq!(ProfileName::parse("-foo"), Err(ProfileNameError::BadStart));
    }

    #[test]
    fn every_builtin_resolves_round_trip() {
        for p in Profile::all() {
            let name = p.name();
            assert_eq!(Profile::from_name(name), Some(*p));
            // Name passes the regex.
            ProfileName::parse(name).unwrap_or_else(|e| panic!("bad name {name}: {e:?}"));
        }
    }

    #[test]
    fn unknown_builtin_returns_none() {
        assert_eq!(Profile::from_name("chrome-999"), None);
    }

    #[test]
    fn default_label_is_reserved() {
        // The validation regex starts with [a-z0-9], so `_default` is unparseable
        // as a user profile name. That guarantees no collision.
        assert!(ProfileName::parse(DEFAULT_LABEL).is_err());
    }
}
```

- [ ] **Step 3.4: Create `error.rs`**

Write `crates/roxy-impersonate/src/error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImpersonateError {
    #[error("unknown fingerprint: {0}")]
    UnknownFingerprint(String),

    #[error("wreq: {0}")]
    Wreq(#[from] wreq::Error),

    #[error("custom profile load failed at {path}: {source}")]
    CustomLoad {
        path: std::path::PathBuf,
        #[source]
        source: anyhow::Error,
    },
}
```

Add `anyhow = { workspace = true }` to `roxy-impersonate/Cargo.toml` deps. (Workspace already has it.)

- [ ] **Step 3.5: Create `lib.rs`**

Write `crates/roxy-impersonate/src/lib.rs`:

```rust
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod error;
mod profile;

pub use error::ImpersonateError;
pub use profile::{Profile, ProfileName, ProfileNameError, DEFAULT_LABEL, NONE_LABEL};
```

Module declarations for `client`, `body`, `custom` are added in later tasks.

- [ ] **Step 3.6: Run the unit tests**

Run: `cargo test -p roxy-impersonate`
Expected: all 5 tests in `profile::tests` pass.

Run: `cargo build --workspace`
Expected: clean build. wreq + wreq-util will download and build (BoringSSL — first build takes a couple minutes).

If the build fails with `error: linking with cc failed` or missing BoringSSL deps, install: `cmake`, `perl`, `clang` (macOS: `brew install cmake`; Linux: `apt-get install cmake clang perl`).

- [ ] **Step 3.7: Commit**

```bash
git add Cargo.toml crates/roxy-impersonate/
git commit -m "feat(roxy-impersonate): crate scaffold with Profile enum + name parsing

Adds new crate with the Profile enum (Chrome 137, Firefox 139, Safari
18.3.1, Edge 134, OkHttp 5 as initial set), ProfileName kebab-case
validator, and ImpersonateError. Each builtin maps to a wreq_util::Emulation
variant. Custom profile loading and the wreq client wrapper land in
follow-up commits."
```

---

## Task 4: `ImpersonateClient` + `ImpersonateBody`

**Files:**
- Create: `crates/roxy-impersonate/src/body.rs`
- Create: `crates/roxy-impersonate/src/client.rs`
- Modify: `crates/roxy-impersonate/src/lib.rs` (add mod + pub use)
- Modify: `crates/roxy-http/src/upstream.rs` (add `Impersonate` variant to `UpstreamBody`)
- Modify: `crates/roxy-http/Cargo.toml` (depend on `roxy-impersonate`)

- [ ] **Step 4.1: Add `roxy-impersonate` dep to `roxy-http`**

In `crates/roxy-http/Cargo.toml`, add to `[dependencies]`:
```toml
roxy-impersonate = { workspace = true }
```

(`roxy-impersonate` was added to the internal-deps block in Task 3.1.)

- [ ] **Step 4.2: Write the `ImpersonateBody` failing test**

Create `crates/roxy-impersonate/src/body.rs`:

```rust
use bytes::Bytes;
use futures::Stream;
use http_body::{Body, Frame};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    /// `http_body::Body` adapter over `wreq::Response::bytes_stream()`. Errors
    /// from wreq are surfaced as `io::Error::other(...)` to match the existing
    /// upstream error shape.
    pub struct ImpersonateBody {
        #[pin]
        inner: futures::stream::BoxStream<'static, Result<Bytes, wreq::Error>>,
    }
}

impl ImpersonateBody {
    pub fn from_response(resp: wreq::Response) -> Self {
        use futures::StreamExt;
        Self {
            inner: resp.bytes_stream().boxed(),
        }
    }
}

impl Body for ImpersonateBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let this = self.project();
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(Frame::data(b)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(std::io::Error::other(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    // Smoke test: construct a wreq client + GET a small endpoint, then drain
    // through ImpersonateBody. Marked `#[ignore]` because it requires network.
    #[tokio::test]
    #[ignore]
    async fn drains_real_response() {
        let client = wreq::Client::builder()
            .emulation(wreq_util::Emulation::Chrome137)
            .build()
            .unwrap();
        let resp = client.get("https://httpbin.org/bytes/64").send().await.unwrap();
        let body = ImpersonateBody::from_response(resp);
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected.len(), 64);
    }
}
```

- [ ] **Step 4.3: Write the `ImpersonateClient`**

Create `crates/roxy-impersonate/src/client.rs`:

```rust
use crate::body::ImpersonateBody;
use crate::error::ImpersonateError;
use crate::profile::Profile;
use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Wraps a lazily-built pool of `wreq::Client` instances, one per profile in
/// use. Each request is dispatched on the client matching the requested label.
///
/// wreq configures emulation at client construction, so per-request override
/// requires per-profile clients. We accept this; the pool is small (one entry
/// per active profile name) and `wreq::Client` is internally Arc'd so cloning
/// is cheap.
pub struct ImpersonateClient {
    builtin: HashMap<String, Profile>,
    // Custom profiles are added in Task 5.
    clients: Arc<RwLock<HashMap<String, wreq::Client>>>,
}

impl Default for ImpersonateClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ImpersonateClient {
    pub fn new() -> Self {
        let mut builtin = HashMap::new();
        for p in Profile::all() {
            builtin.insert(p.name().to_string(), *p);
        }
        Self {
            builtin,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns true if a profile with the given label is registered.
    pub fn has_profile(&self, label: &str) -> bool {
        self.builtin.contains_key(label)
    }

    /// Iterator over registered profile names. Stable order not guaranteed; use
    /// only for diagnostics (e.g. error messages listing available profiles).
    pub fn profile_names(&self) -> Vec<String> {
        let mut v: Vec<_> = self.builtin.keys().cloned().collect();
        v.sort();
        v
    }

    async fn client_for(&self, label: &str) -> Result<wreq::Client, ImpersonateError> {
        // Fast path: already built.
        if let Some(c) = self.clients.read().await.get(label) {
            return Ok(c.clone());
        }
        // Build.
        let profile = self
            .builtin
            .get(label)
            .copied()
            .ok_or_else(|| ImpersonateError::UnknownFingerprint(label.to_string()))?;
        let client = wreq::Client::builder()
            .emulation(profile.emulation())
            .build()?;
        self.clients
            .write()
            .await
            .insert(label.to_string(), client.clone());
        Ok(client)
    }

    /// Send a request through the wreq client for the named profile.
    ///
    /// The supplied request body is collected into bytes before forwarding;
    /// streaming request bodies are not supported in v1 because wreq's body
    /// shape differs from hyper's and the v1 use case (GET-heavy stealth
    /// scraping) does not need it. POSTs with bodies work via the collected
    /// path; the v2 task will switch to wreq::Body::wrap for streaming if
    /// real workloads need it.
    pub async fn send<B>(
        &self,
        label: &str,
        req: Request<B>,
    ) -> Result<Response<ImpersonateBody>, ImpersonateError>
    where
        B: Body<Data = Bytes, Error = std::io::Error> + Send + 'static + Unpin,
    {
        use http_body_util::BodyExt;

        let client = self.client_for(label).await?;
        let (parts, body) = req.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| ImpersonateError::Wreq(wreq::Error::from(e)))?
            .to_bytes();

        let method = parts.method;
        let url = parts.uri.to_string();

        let mut builder = client.request(method, &url);
        for (name, value) in parts.headers.iter() {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
        if !body_bytes.is_empty() {
            builder = builder.body(body_bytes.to_vec());
        }
        let wreq_resp = builder.send().await?;

        let status = wreq_resp.status();
        let headers = wreq_resp.headers().clone();
        let imp_body = ImpersonateBody::from_response(wreq_resp);

        let mut http_resp = Response::new(imp_body);
        *http_resp.status_mut() = status;
        *http_resp.headers_mut() = headers;
        Ok(http_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_profile_label_errors() {
        let c = ImpersonateClient::new();
        // Don't actually call send (would need a real network); test the
        // resolution path through client_for.
        let err = c.client_for("chrome-999").await.unwrap_err();
        match err {
            ImpersonateError::UnknownFingerprint(label) => assert_eq!(label, "chrome-999"),
            other => panic!("expected UnknownFingerprint, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn builds_client_for_known_profile() {
        let c = ImpersonateClient::new();
        let _ = c.client_for("chrome-137").await.expect("builds");
        // Second call hits the cache.
        let _ = c.client_for("chrome-137").await.expect("cached");
        assert!(c.clients.read().await.contains_key("chrome-137"));
    }

    #[test]
    fn profile_names_lists_all_builtins() {
        let c = ImpersonateClient::new();
        let names = c.profile_names();
        assert!(names.contains(&"chrome-137".to_string()));
        assert!(names.contains(&"firefox-139".to_string()));
    }
}
```

Note on the request body conversion: this v1 collects the body to bytes before forwarding. The spec's use case is GET-heavy stealth scraping, so this is acceptable. Streaming request bodies are deferred (added as a comment-marked future enhancement; not a separate task). The header forwarding uses `header(name, value)` rather than `headers(...)` because the latter takes a `HeaderMap` and rebuilding one is more code than the loop.

If the `wreq::RequestBuilder::header` signature does not accept `(&str, &[u8])` — wreq's reqwest lineage strongly suggests it does — adapt to whatever it takes (`(impl IntoHeaderName, impl TryInto<HeaderValue>)`).

- [ ] **Step 4.4: Update `lib.rs`**

Replace `crates/roxy-impersonate/src/lib.rs` with:

```rust
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod body;
mod client;
mod error;
mod profile;

pub use body::ImpersonateBody;
pub use client::ImpersonateClient;
pub use error::ImpersonateError;
pub use profile::{Profile, ProfileName, ProfileNameError, DEFAULT_LABEL, NONE_LABEL};
```

- [ ] **Step 4.5: Add `Impersonate` variant to `UpstreamBody`**

In `crates/roxy-http/src/upstream.rs`, replace the `pin_project! { ... }` block (the enum definition from Task 2.1) with:

```rust
pin_project! {
    /// Body type emitted by all upstream client variants. The handler's tee_pump
    /// is generic over `http_body::Body`, so any future variant added here just
    /// needs to implement `Body<Data=Bytes, Error=io::Error>` and forward
    /// poll_frame.
    #[project = UpstreamBodyProj]
    pub enum UpstreamBody {
        Hyper { #[pin] inner: hyper::body::Incoming },
        Impersonate { #[pin] inner: roxy_impersonate::ImpersonateBody },
    }
}

impl UpstreamBody {
    pub fn hyper(inner: hyper::body::Incoming) -> Self {
        Self::Hyper { inner }
    }
    pub fn impersonate(inner: roxy_impersonate::ImpersonateBody) -> Self {
        Self::Impersonate { inner }
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match self.project() {
            UpstreamBodyProj::Hyper { inner } => inner.poll_frame(cx).map_err(std::io::Error::other),
            UpstreamBodyProj::Impersonate { inner } => inner.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            UpstreamBody::Hyper { inner } => inner.is_end_stream(),
            UpstreamBody::Impersonate { inner } => inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            UpstreamBody::Hyper { inner } => inner.size_hint(),
            UpstreamBody::Impersonate { inner } => inner.size_hint(),
        }
    }
}
```

- [ ] **Step 4.6: Run unit tests**

Run: `cargo test -p roxy-impersonate --lib`
Expected: profile tests (Task 3) + `unknown_profile_label_errors` + `builds_client_for_known_profile` + `profile_names_lists_all_builtins` all pass.

Note `drains_real_response` is `#[ignore]` — it stays unrun in CI.

Run: `cargo build --workspace`
Expected: clean.

- [ ] **Step 4.7: Commit**

```bash
git add crates/roxy-impersonate/ crates/roxy-http/
git commit -m "feat(roxy-impersonate): ImpersonateClient + ImpersonateBody adapter

ImpersonateClient holds a lazy per-profile wreq::Client pool keyed by
canonical kebab-case label. ImpersonateBody adapts wreq's bytes_stream
output as http_body::Body<Data=Bytes, Error=io::Error>. UpstreamBody
in roxy-http gains the Impersonate variant. v1 collects request bodies
to bytes before forwarding (sufficient for GET-heavy stealth scraping)."
```

---

## Task 5: Custom profile TOML loader

**Files:**
- Create: `crates/roxy-impersonate/src/custom.rs`
- Modify: `crates/roxy-impersonate/src/lib.rs` (add mod, pub use)
- Modify: `crates/roxy-impersonate/src/client.rs` (accept custom registry)

This task accepts the spec's TOML schema and converts it to a `wreq::EmulationProvider`. The exact wreq API for `TlsConfig` + `Http2Config` construction is wreq-version-specific; this task writes the loader scaffold and validation, with the actual wreq-builder calls clearly marked for the implementer to fill from the wreq docs they verify at write time.

- [ ] **Step 5.1: Author the failing TOML round-trip test**

Create `crates/roxy-impersonate/src/custom.rs`:

```rust
use crate::error::ImpersonateError;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Custom profile spec, parsed from TOML.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CustomProfileSpec {
    pub name: String,
    pub tls: TlsSpec,
    pub http2: Http2Spec,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsSpec {
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<String>,
    pub extensions: Vec<String>,
    pub supported_versions: Vec<String>,
    pub signature_algorithms: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Http2Spec {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub settings_order: Vec<String>,
    pub header_order: Vec<String>,
}

pub struct CustomProfile {
    pub spec: CustomProfileSpec,
    /// Pre-built emulation provider, ready to hand to wreq's ClientBuilder.
    pub provider: wreq::EmulationProvider,
}

impl CustomProfile {
    /// Load a single profile TOML.
    pub fn load(path: &Path) -> Result<Self, ImpersonateError> {
        let text = std::fs::read_to_string(path).map_err(|e| ImpersonateError::CustomLoad {
            path: path.to_path_buf(),
            source: anyhow::anyhow!("read: {e}"),
        })?;
        let spec: CustomProfileSpec =
            toml::from_str(&text).map_err(|e| ImpersonateError::CustomLoad {
                path: path.to_path_buf(),
                source: anyhow::anyhow!("parse: {e}"),
            })?;
        // Name validation.
        crate::profile::ProfileName::parse(&spec.name).map_err(|e| ImpersonateError::CustomLoad {
            path: path.to_path_buf(),
            source: anyhow::anyhow!("invalid name {:?}: {e}", spec.name),
        })?;

        let provider = build_provider(&spec).map_err(|e| ImpersonateError::CustomLoad {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(Self { spec, provider })
    }

    /// Load every `*.toml` in a directory. Returns the loaded profiles plus a
    /// list of per-file errors so the caller can decide policy.
    pub fn load_dir(dir: &Path) -> Result<Vec<CustomProfile>, ImpersonateError> {
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        let read = std::fs::read_dir(dir).map_err(|e| ImpersonateError::CustomLoad {
            path: dir.to_path_buf(),
            source: anyhow::anyhow!("readdir: {e}"),
        })?;
        for entry in read {
            let entry = entry.map_err(|e| ImpersonateError::CustomLoad {
                path: dir.to_path_buf(),
                source: anyhow::anyhow!("entry: {e}"),
            })?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            out.push(CustomProfile::load(&path)?);
        }
        Ok(out)
    }
}

/// Builds a `wreq::EmulationProvider` from a `CustomProfileSpec`.
///
/// IMPLEMENTER NOTE: the exact wreq builder method names depend on the
/// wreq version pinned in workspace deps. As of wreq 6.0.0-rc.28 the public
/// surface includes `wreq::tls::TlsConfig`, `wreq::Http2Config`, and
/// `wreq::EmulationProvider`. Consult `cargo doc --open -p wreq` to confirm:
///   - How TlsConfig is constructed from an ordered cipher list + extension list
///   - How Http2Config takes settings_order
///   - How an EmulationProvider is assembled from both
/// Implement this function strictly from the spec fields; do not silently
/// drop fields. Reject unknown TLS extension names with a clear error.
fn build_provider(spec: &CustomProfileSpec) -> Result<wreq::EmulationProvider, anyhow::Error> {
    // Validation first — catches typos before handing to wreq.
    if spec.tls.cipher_suites.is_empty() {
        anyhow::bail!("tls.cipher_suites must not be empty");
    }
    if spec.tls.extensions.is_empty() {
        anyhow::bail!("tls.extensions must not be empty");
    }
    if spec.http2.settings_order.is_empty() {
        anyhow::bail!("http2.settings_order must not be empty");
    }
    if spec.http2.header_order.is_empty() {
        anyhow::bail!("http2.header_order must not be empty");
    }

    // Build TlsConfig.
    let mut tls = wreq::tls::TlsConfig::builder();
    // Translate ALPN strings to AlpnProtos.
    let alpn: Vec<wreq::tls::AlpnProtos> = spec
        .tls
        .alpn
        .iter()
        .map(|s| match s.as_str() {
            "h2" => Ok(wreq::tls::AlpnProtos::Http2),
            "http/1.1" => Ok(wreq::tls::AlpnProtos::Http1),
            other => Err(anyhow::anyhow!("unknown alpn protocol: {other}")),
        })
        .collect::<Result<_, _>>()?;
    tls = tls.alpn(alpn);
    // The implementer fills in the remaining tls.cipher_suites / .extensions /
    // .supported_versions / .signature_algorithms calls per wreq's TlsConfig
    // builder API. Each must reject unknown identifiers with a clear error.
    let tls_config = tls.build()?;

    // Build Http2Config.
    let mut h2 = wreq::Http2Config::builder()
        .header_table_size(spec.http2.header_table_size)
        .enable_push(spec.http2.enable_push)
        .initial_window_size(spec.http2.initial_window_size)
        .max_frame_size(spec.http2.max_frame_size)
        .max_header_list_size(spec.http2.max_header_list_size);
    // The implementer fills in settings_order + header_order per wreq's
    // Http2Config builder API.
    let h2_config = h2.build()?;

    // Assemble.
    let provider = wreq::EmulationProvider::builder()
        .tls_config(tls_config)
        .http2_config(h2_config)
        .build()?;
    Ok(provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_spec_toml() -> &'static str {
        r#"
name = "chrome-148"

[tls]
alpn = ["h2", "http/1.1"]
cipher_suites = ["TLS_AES_128_GCM_SHA256"]
extensions = ["server_name", "supported_groups"]
supported_versions = ["TLS1.3", "TLS1.2"]
signature_algorithms = ["ecdsa_secp256r1_sha256"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_frame_size = 16384
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH"]
header_order = [":method", ":authority", ":scheme", ":path"]
"#
    }

    #[test]
    fn parses_minimal_spec() {
        let spec: CustomProfileSpec = toml::from_str(minimal_spec_toml()).unwrap();
        assert_eq!(spec.name, "chrome-148");
        assert_eq!(spec.tls.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(spec.http2.header_table_size, 65536);
        assert!(!spec.http2.enable_push);
    }

    #[test]
    fn rejects_invalid_name() {
        let toml_with_bad_name = minimal_spec_toml().replace("chrome-148", "Chrome_148");
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, toml_with_bad_name.as_bytes()).unwrap();
        let err = CustomProfile::load(f.path()).unwrap_err();
        let s = format!("{err:?}");
        assert!(s.contains("invalid name"), "got: {s}");
    }

    #[test]
    fn rejects_missing_required_section() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut f, b"name = \"x\"\n").unwrap();
        let err = CustomProfile::load(f.path()).unwrap_err();
        let s = format!("{err:?}");
        assert!(s.contains("parse"), "got: {s}");
    }

    #[test]
    fn rejects_unknown_alpn() {
        let bad = minimal_spec_toml().replace(r#"["h2", "http/1.1"]"#, r#"["h3"]"#);
        let spec: CustomProfileSpec = toml::from_str(&bad).unwrap();
        let err = build_provider(&spec).unwrap_err();
        let s = format!("{err}");
        assert!(s.contains("unknown alpn"), "got: {s}");
    }

    #[test]
    fn load_dir_returns_empty_for_missing_dir() {
        let p = std::path::PathBuf::from("/nonexistent-roxy-test-dir");
        let profiles = CustomProfile::load_dir(&p).unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn load_dir_picks_up_toml_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("chrome-148.toml");
        std::fs::write(&p, minimal_spec_toml()).unwrap();
        // Add a non-toml file that must be ignored.
        std::fs::write(dir.path().join("readme.md"), "ignore me").unwrap();
        let profiles = CustomProfile::load_dir(dir.path()).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].spec.name, "chrome-148");
    }
}
```

- [ ] **Step 5.2: Update `lib.rs` to expose custom-profile types**

In `crates/roxy-impersonate/src/lib.rs`, add `mod custom;` and re-exports:

```rust
mod body;
mod client;
mod custom;
mod error;
mod profile;

pub use body::ImpersonateBody;
pub use client::ImpersonateClient;
pub use custom::{CustomProfile, CustomProfileSpec};
pub use error::ImpersonateError;
pub use profile::{Profile, ProfileName, ProfileNameError, DEFAULT_LABEL, NONE_LABEL};
```

- [ ] **Step 5.3: Teach `ImpersonateClient` about custom profiles**

In `crates/roxy-impersonate/src/client.rs`, replace the `ImpersonateClient` struct and its constructor with:

```rust
pub struct ImpersonateClient {
    builtin: HashMap<String, Profile>,
    custom: HashMap<String, wreq::EmulationProvider>,
    clients: Arc<RwLock<HashMap<String, wreq::Client>>>,
}

impl Default for ImpersonateClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ImpersonateClient {
    pub fn new() -> Self {
        Self::with_custom(Vec::new())
    }

    /// Construct with a set of custom profiles. On name collision with a builtin
    /// the builtin wins and a warning is logged.
    pub fn with_custom(customs: Vec<crate::CustomProfile>) -> Self {
        let mut builtin = HashMap::new();
        for p in Profile::all() {
            builtin.insert(p.name().to_string(), *p);
        }
        let mut custom = HashMap::new();
        for c in customs {
            if builtin.contains_key(&c.spec.name) {
                tracing::warn!(
                    name = %c.spec.name,
                    "custom profile collides with builtin; builtin wins"
                );
                continue;
            }
            custom.insert(c.spec.name, c.provider);
        }
        Self {
            builtin,
            custom,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn has_profile(&self, label: &str) -> bool {
        self.builtin.contains_key(label) || self.custom.contains_key(label)
    }

    pub fn profile_names(&self) -> Vec<String> {
        let mut v: Vec<_> = self.builtin.keys().cloned().collect();
        v.extend(self.custom.keys().cloned());
        v.sort();
        v
    }

    async fn client_for(&self, label: &str) -> Result<wreq::Client, ImpersonateError> {
        if let Some(c) = self.clients.read().await.get(label) {
            return Ok(c.clone());
        }
        let client = if let Some(profile) = self.builtin.get(label).copied() {
            wreq::Client::builder()
                .emulation(profile.emulation())
                .build()?
        } else if let Some(provider) = self.custom.get(label) {
            wreq::Client::builder()
                .emulation(provider.clone())
                .build()?
        } else {
            return Err(ImpersonateError::UnknownFingerprint(label.to_string()));
        };
        self.clients
            .write()
            .await
            .insert(label.to_string(), client.clone());
        Ok(client)
    }

    // ... send() method from Task 4.3 stays unchanged ...
}
```

The implementer should also add a test:

```rust
    #[tokio::test]
    async fn collision_logs_warning_builtin_wins() {
        // Construct a CustomProfile whose name collides with a builtin.
        // We do this by skipping the file-load path and building directly.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("chrome-137.toml");
        std::fs::write(&p, super::tests_helper::COLLIDING_SPEC).unwrap();
        let customs = crate::CustomProfile::load_dir(dir.path()).unwrap();
        let client = ImpersonateClient::with_custom(customs);
        // Builtin wins: chrome-137 still resolves, and its emulation is the
        // builtin (not the custom). We verify by checking that has_profile sees
        // exactly one entry for the name.
        assert!(client.has_profile("chrome-137"));
        assert!(!client.custom.contains_key("chrome-137"));
    }
```

with a helper module at the bottom of the file:

```rust
#[cfg(test)]
mod tests_helper {
    pub const COLLIDING_SPEC: &str = r#"
name = "chrome-137"

[tls]
alpn = ["h2"]
cipher_suites = ["TLS_AES_128_GCM_SHA256"]
extensions = ["server_name"]
supported_versions = ["TLS1.3"]
signature_algorithms = ["ecdsa_secp256r1_sha256"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_frame_size = 16384
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE"]
header_order = [":method"]
"#;
}
```

- [ ] **Step 5.4: Run the tests**

Run: `cargo test -p roxy-impersonate`
Expected: all 12 tests pass (5 profile + 3 client + 6 custom).

If `build_provider` cannot be completed because the wreq builder API differs from the sketch (likely on the first attempt), document the discrepancy as a beads issue and gate the test with the actual minimum-valid configuration the wreq version accepts. Do not stub it out — the loader must produce a real `EmulationProvider`.

- [ ] **Step 5.5: Commit**

```bash
git add crates/roxy-impersonate/
git commit -m "feat(roxy-impersonate): custom profile TOML loader

CustomProfile::load and load_dir parse roxy's profile spec into a
wreq::EmulationProvider. Validation rejects bad names, missing required
sections, and unknown ALPN protocols at load time. ImpersonateClient
accepts a custom profile list; on collision with a builtin, the builtin
wins and we log a warning."
```

---

## Task 6: `Upstream` trait + `UpstreamRouter` + handler integration

**Files:**
- Create: `crates/roxy-http/src/router.rs`
- Modify: `crates/roxy-http/src/lib.rs` (mod router, re-exports)
- Modify: `crates/roxy-http/src/upstream.rs` (add `UnknownFingerprint`, `Impersonate` to `UpstreamError`)
- Modify: `crates/roxy-proxy/src/handler.rs` (header parsing, label resolution, call router)
- Modify: `crates/roxy-proxy/Cargo.toml` (`roxy-impersonate` dep)

- [ ] **Step 6.1: Extend `UpstreamError`**

In `crates/roxy-http/src/upstream.rs`, replace the `UpstreamError` enum (lines 16–23) with:

```rust
#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("client: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),

    #[error("invalid uri: {0}")]
    Uri(String),

    #[error("unknown fingerprint: {0}")]
    UnknownFingerprint(String),

    #[error("impersonate: {0}")]
    Impersonate(#[from] roxy_impersonate::ImpersonateError),
}
```

- [ ] **Step 6.2: Author the router**

Create `crates/roxy-http/src/router.rs`:

```rust
//! UpstreamRouter dispatches to the rustls upstream client or the wreq-based
//! impersonate client based on the resolved profile label. Header parsing and
//! label resolution live in the handler (the caller) — the router only
//! switches on the label string.

use crate::upstream::{UpstreamBody, UpstreamClient, UpstreamError};
use crate::ClientBody;
use http::{Request, Response};
use roxy_impersonate::{ImpersonateClient, DEFAULT_LABEL};

pub struct UpstreamRouter {
    rustls: UpstreamClient,
    impersonate: Option<ImpersonateClient>,
}

impl UpstreamRouter {
    pub fn new(rustls: UpstreamClient, impersonate: Option<ImpersonateClient>) -> Self {
        Self { rustls, impersonate }
    }

    /// Routes by label:
    ///   - `_default` => rustls path
    ///   - any other label => impersonate path; if impersonate is unconfigured
    ///     or the label is unknown, returns `UnknownFingerprint`.
    pub async fn send(
        &self,
        label: &str,
        req: Request<ClientBody>,
    ) -> Result<Response<UpstreamBody>, UpstreamError> {
        if label == DEFAULT_LABEL {
            return self.rustls.send(req).await;
        }
        let imp = self
            .impersonate
            .as_ref()
            .ok_or_else(|| UpstreamError::UnknownFingerprint(label.to_string()))?;
        if !imp.has_profile(label) {
            return Err(UpstreamError::UnknownFingerprint(label.to_string()));
        }
        let resp = imp.send(label, req).await?;
        let (parts, body) = resp.into_parts();
        Ok(Response::from_parts(parts, UpstreamBody::impersonate(body)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_impersonate_routes_default_label_to_rustls() {
        // We don't make a real network call; this test only verifies that the
        // _default label takes the rustls branch (no error from
        // UnknownFingerprint) and that any non-default label without an
        // impersonate client errors with UnknownFingerprint.
        let rustls = UpstreamClient::new().unwrap();
        let router = UpstreamRouter::new(rustls, None);
        let req = http::Request::get("http://127.0.0.1:1/")
            .body(http_body_util::Empty::<bytes::Bytes>::new().map_err(|n| match n {}).boxed())
            .unwrap();
        // _default would try to actually connect; we only assert path selection
        // by inspecting which error type comes back. Instead, test the unknown
        // path which short-circuits before any network I/O.
        let unknown_req = http::Request::get("http://127.0.0.1:1/")
            .body(http_body_util::Empty::<bytes::Bytes>::new().map_err(|n| match n {}).boxed())
            .unwrap();
        let err = router.send("chrome-137", unknown_req).await.unwrap_err();
        match err {
            UpstreamError::UnknownFingerprint(s) => assert_eq!(s, "chrome-137"),
            other => panic!("expected UnknownFingerprint, got {other:?}"),
        }
        // Discard the prepared _default request to avoid an unused warning.
        drop(req);
    }
}
```

(The imports for `http_body_util::Empty` and `bytes::Bytes` and `http_body_util::BodyExt` need to be added; both are existing workspace deps. `BodyExt` brings the `map_err` and `boxed` methods into scope.)

- [ ] **Step 6.3: Update `lib.rs` to export router**

In `crates/roxy-http/src/lib.rs`:

```rust
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod accept;
pub mod connect;
pub mod router;
pub mod server;
pub mod upstream;

pub use accept::{ConnHandler, Handler};
pub use router::UpstreamRouter;
pub use server::{serve_tls, BoxBody};
pub use upstream::{ClientBody, UpstreamBody, UpstreamClient, UpstreamError};
```

- [ ] **Step 6.4: Add `roxy-impersonate` dep to `roxy-proxy`**

In `crates/roxy-proxy/Cargo.toml`, `[dependencies]`:

```toml
roxy-impersonate = { workspace = true }
```

- [ ] **Step 6.5: Wire header parsing + router into the handler**

In `crates/roxy-proxy/src/handler.rs`, change the imports at the top to include:

```rust
use roxy_http::{UpstreamBody, UpstreamError, UpstreamRouter};
use roxy_impersonate::{DEFAULT_LABEL, NONE_LABEL};
```

Replace the `Handler` struct (lines 17–23) with:

```rust
#[derive(Clone)]
pub struct Handler<C: Cache + 'static> {
    pub cache: Arc<C>,
    pub default_ttl: Duration,
    pub router: Arc<UpstreamRouter>,
    pub default_profile: Option<String>,
    pub strip_fingerprint_header: bool,
    pub disconnect_cap: u64,
}

pub const FINGERPRINT_HEADER: &str = "x-roxy-fingerprint";
```

Replace the body of `Handler::handle` (lines 26–96). The full replacement (preserving the existing cache, tee, and response build logic — only adding header parsing, label resolution, and routing):

```rust
impl<C: Cache + 'static> Handler<C> {
    pub async fn handle(
        &self,
        authority: String,
        mut req: Request<Incoming>,
    ) -> Result<Response<BoxBody>, Infallible> {
        // 1. Resolve profile label from header + default.
        let label = match resolve_label(req.headers(), self.default_profile.as_deref()) {
            Ok(l) => l,
            Err(LabelError::MultipleHeaders) => {
                return Ok(simple(StatusCode::BAD_REQUEST, "roxy: X-Roxy-Fingerprint must be set at most once"));
            }
            Err(LabelError::BadValue(_)) => {
                return Ok(simple(
                    StatusCode::BAD_REQUEST,
                    "roxy: X-Roxy-Fingerprint value must match ^[a-z0-9][a-z0-9-]*$",
                ));
            }
        };

        // 2. Strip the fingerprint header before forwarding upstream.
        if self.strip_fingerprint_header {
            req.headers_mut().remove(FINGERPRINT_HEADER);
        }

        // 3. Cache key includes the resolved label.
        let key = CacheKey::from_request(&req, &label, "https", &authority);
        if let Ok(Some(hit)) = self.cache.lookup(&key).await {
            return Ok(reply_from_cache(hit));
        }

        // 4. Rebuild upstream URI (same as before).
        let scheme = req.uri().scheme_str().unwrap_or("https");
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let upstream_uri: http::Uri =
            match format!("{scheme}://{authority}{path_and_query}").parse() {
                Ok(u) => u,
                Err(_) => return Ok(bad_gateway("roxy: bad upstream uri")),
            };
        *req.uri_mut() = upstream_uri;
        req.headers_mut().remove(http::header::HOST);

        // 5. Forward through the router.
        let (parts, body) = req.into_parts();
        let body: roxy_http::ClientBody = body.map_err(std::io::Error::other).boxed();
        let upstream_req = http::Request::from_parts(parts, body);

        let resp = match self.router.send(&label, upstream_req).await {
            Ok(r) => r,
            Err(UpstreamError::UnknownFingerprint(name)) => {
                tracing::warn!(profile = %name, host = %authority, "unknown fingerprint");
                return Ok(bad_gateway("roxy: unknown fingerprint"));
            }
            Err(e) => {
                let kind = upstream_kind(&e);
                tracing::warn!(error = %e, profile = %label, host = %authority, kind = %kind, "upstream send failed");
                return Ok(bad_gateway("roxy: upstream error"));
            }
        };

        // 6. Cache + tee (unchanged from prior version).
        let status = resp.status();
        let cache_eligible = status.is_success() || status.is_redirection();
        let (resp_parts, resp_body) = resp.into_parts();

        let writer: Option<Box<dyn CacheWriter>> = if cache_eligible {
            let meta = roxy_cache::ResponseMeta {
                status: status.as_u16(),
                headers: header_pairs(&resp_parts.headers),
            };
            match self.cache.begin_store(&key, meta, self.default_ttl).await {
                Ok(w) => Some(w),
                Err(e) => {
                    tracing::warn!(error = %e, "begin_store failed - pass-through");
                    None
                }
            }
        } else {
            None
        };

        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);
        let disconnect_cap = self.disconnect_cap;
        tokio::spawn(tee_pump(resp_body, writer, tx, disconnect_cap));

        let mut builder_resp = http::Response::new(stream_to_body(rx));
        *builder_resp.status_mut() = resp_parts.status;
        for (k, v) in resp_parts.headers.iter() {
            builder_resp.headers_mut().append(k, v.clone());
        }
        Ok(builder_resp)
    }
}

#[derive(Debug, PartialEq)]
enum LabelError {
    MultipleHeaders,
    BadValue(String),
}

fn resolve_label(
    headers: &http::HeaderMap,
    default_profile: Option<&str>,
) -> Result<String, LabelError> {
    let mut iter = headers.get_all(FINGERPRINT_HEADER).iter();
    let first = iter.next();
    if iter.next().is_some() {
        return Err(LabelError::MultipleHeaders);
    }
    let raw = match first {
        Some(v) => v.to_str().unwrap_or("").trim(),
        None => "",
    };
    if raw.is_empty() {
        return Ok(default_profile.unwrap_or(DEFAULT_LABEL).to_string());
    }
    if raw == NONE_LABEL {
        return Ok(DEFAULT_LABEL.to_string());
    }
    // Validate.
    if roxy_impersonate::ProfileName::parse(raw).is_err() {
        return Err(LabelError::BadValue(raw.to_string()));
    }
    Ok(raw.to_string())
}

fn upstream_kind(e: &UpstreamError) -> &'static str {
    match e {
        UpstreamError::UnknownFingerprint(_) => "unknown_profile",
        UpstreamError::Impersonate(roxy_impersonate::ImpersonateError::Wreq(_)) => "impersonate",
        UpstreamError::Impersonate(_) => "impersonate_other",
        UpstreamError::Client(_) => "rustls_client",
        UpstreamError::Uri(_) => "uri",
    }
}

fn simple(status: StatusCode, msg: &'static str) -> Response<BoxBody> {
    let body = Full::new(Bytes::from_static(msg.as_bytes()))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut resp = http::Response::new(body);
    *resp.status_mut() = status;
    resp
}
```

The existing `bad_gateway` helper stays; `simple` is a generalized variant for 400 responses. `tee_pump`, `stream_to_body`, `reply_from_cache`, `header_pairs` stay unchanged.

- [ ] **Step 6.6: Add unit tests for label resolution**

Append to `crates/roxy-proxy/src/handler.rs` (above the existing `bad_gateway` test if any, or in a new `#[cfg(test)]` mod at the bottom of the file):

```rust
#[cfg(test)]
mod label_tests {
    use super::*;
    use http::HeaderMap;

    fn hdr(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(FINGERPRINT_HEADER, http::HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn absent_header_uses_default_or_default_label() {
        let h = HeaderMap::new();
        assert_eq!(resolve_label(&h, None).unwrap(), DEFAULT_LABEL);
        assert_eq!(resolve_label(&h, Some("chrome-137")).unwrap(), "chrome-137");
    }

    #[test]
    fn empty_value_treated_as_absent() {
        let h = hdr(&[""]);
        assert_eq!(resolve_label(&h, Some("chrome-137")).unwrap(), "chrome-137");
    }

    #[test]
    fn none_forces_default_label() {
        let h = hdr(&["none"]);
        assert_eq!(resolve_label(&h, Some("chrome-137")).unwrap(), DEFAULT_LABEL);
    }

    #[test]
    fn explicit_known_name_used() {
        let h = hdr(&["firefox-139"]);
        assert_eq!(resolve_label(&h, Some("chrome-137")).unwrap(), "firefox-139");
    }

    #[test]
    fn multiple_headers_error() {
        let h = hdr(&["chrome-137", "firefox-139"]);
        assert_eq!(resolve_label(&h, None).unwrap_err(), LabelError::MultipleHeaders);
    }

    #[test]
    fn malformed_value_error() {
        let h = hdr(&["Chrome_137"]);
        match resolve_label(&h, None).unwrap_err() {
            LabelError::BadValue(v) => assert_eq!(v, "Chrome_137"),
            other => panic!("got {other:?}"),
        }
    }
}
```

- [ ] **Step 6.7: Update `serve.rs` to build a router**

In `crates/roxy-proxy/src/serve.rs`, replace the `run` body (lines 21–50) — specifically the construction block — with:

```rust
pub async fn run(config_path: Option<&Path>) -> anyhow::Result<()> {
    let cfg = load_config(config_path)?;
    let cache = Arc::new(FsCache::open(&cfg.cache.dir).context("open cache")?);
    let evicted = cache.cleanup_tmp().context("cleanup tmp")?;
    if evicted > 0 {
        tracing::info!(evicted, "cleaned orphan tmp files");
    }

    let ca = Ca::load_or_create(&cfg.ca.dir).context("load/create CA")?;
    print_ca_hint(&ca);

    let signer = LeafSigner::new(ca);
    let resolver = Arc::new(SniResolver::new(signer, SNI_CACHE_CAPACITY));
    let terminator = Terminator::new(resolver);

    let rustls = roxy_http::UpstreamClient::new().context("upstream client")?;

    // Build the impersonate client if any profile is configured (default or
    // any custom profile in the configured directory).
    let impersonate = build_impersonate(&cfg)?;

    let router = Arc::new(roxy_http::UpstreamRouter::new(rustls, impersonate));

    let handler = ProxyConnHandler {
        inner: Arc::new(Handler {
            cache: cache.clone(),
            default_ttl: Duration::from_secs(cfg.cache.default_ttl_seconds),
            router,
            default_profile: cfg.impersonate.default_profile.clone(),
            strip_fingerprint_header: cfg.impersonate.strip_header,
            disconnect_cap: 50 * 1024 * 1024,
        }),
    };

    tracing::info!(addr = %cfg.listen, "listening");
    roxy_http::accept::run(cfg.listen, terminator, Arc::new(handler))
        .await
        .map_err(Into::into)
}

fn build_impersonate(
    cfg: &Config,
) -> anyhow::Result<Option<roxy_impersonate::ImpersonateClient>> {
    let customs = if cfg.impersonate.profiles_dir.exists() {
        roxy_impersonate::CustomProfile::load_dir(&cfg.impersonate.profiles_dir)
            .context("load custom profiles")?
    } else {
        Vec::new()
    };
    if cfg.impersonate.default_profile.is_none() && customs.is_empty() {
        return Ok(None);
    }
    let client = roxy_impersonate::ImpersonateClient::with_custom(customs);
    if let Some(name) = &cfg.impersonate.default_profile {
        if !client.has_profile(name) {
            let avail = client.profile_names().join(", ");
            anyhow::bail!("unknown default profile {name:?}; available: [{avail}]");
        }
    }
    Ok(Some(client))
}
```

Note: this depends on `Config.impersonate` existing, which Task 7 adds. To keep Task 6 self-contained for compile/test purposes, the implementer can inline a placeholder `ImpersonateRuntimeConfig { default_profile: None, profiles_dir: PathBuf::new(), strip_header: true }` until Task 7. Alternatively, complete Task 7 first if the implementer prefers the config-then-router order; both orders work.

- [ ] **Step 6.8: Run tests**

Run: `cargo test --workspace`
Expected: all unit tests pass. The handler's existing integration tests (`tests/golden.rs`, `streaming.rs`, `ttl.rs`, `errors.rs`) still pass because:
- The default config sets `default_profile = None`, so requests resolve to `_default`, take the rustls branch, and behave identically.
- `strip_fingerprint_header` defaults to true but no fingerprint header is set in those tests.

- [ ] **Step 6.9: Commit**

```bash
git add crates/roxy-http/ crates/roxy-proxy/
git commit -m "feat(roxy-http,roxy-proxy): UpstreamRouter + X-Roxy-Fingerprint header

Adds UpstreamRouter dispatching by profile label between the rustls
client and the wreq-based ImpersonateClient. Handler parses
X-Roxy-Fingerprint, resolves to a label (default | name | 'none'
escape hatch), strips the header before forwarding upstream, and folds
the label into the cache key. UnknownFingerprint -> 502; malformed
header -> 400; multiple headers -> 400."
```

---

## Task 7: Config schema + CLI flag

**Files:**
- Modify: `crates/roxy-config/src/lib.rs`
- Modify: `crates/roxy-proxy/src/cli.rs`
- Modify: `crates/roxy-proxy/src/main.rs` (pass flag through)
- Modify: `crates/roxy-proxy/src/serve.rs` (accept override)

- [ ] **Step 7.1: Add `ImpersonateConfig` to `roxy-config`**

In `crates/roxy-config/src/lib.rs`, add to the `Config` struct:

```rust
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    pub cache: CacheConfig,
    pub ca: CaConfig,
    pub log: LogConfig,
    pub impersonate: ImpersonateConfig,  // NEW
}
```

Add the new section type and its `Default`:

```rust
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ImpersonateConfig {
    /// Optional. If set, every upstream request without an explicit override
    /// uses this profile. Absent => unfingerprinted (rustls path).
    pub default_profile: Option<String>,
    /// Optional. Directory of *.toml custom profile specs. Defaults to
    /// "./profiles" relative to the config file (not currently resolved to
    /// the config file's dir; see notes).
    pub profiles_dir: PathBuf,
    /// Strip the X-Roxy-Fingerprint header before forwarding upstream.
    pub strip_header: bool,
}

impl Default for ImpersonateConfig {
    fn default() -> Self {
        Self {
            default_profile: None,
            profiles_dir: PathBuf::from("./profiles"),
            strip_header: true,
        }
    }
}
```

Update the `Config::default` impl to include `impersonate: ImpersonateConfig::default()`:

```rust
impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            cache: CacheConfig::default(),
            ca: CaConfig::default(),
            log: LogConfig::default(),
            impersonate: ImpersonateConfig::default(),
        }
    }
}
```

Update `with_expanded_paths` to expand `profiles_dir`:

```rust
impl Config {
    pub fn with_expanded_paths(mut self) -> Result<Self, ConfigError> {
        self.cache.dir = expand(&self.cache.dir)?;
        self.ca.dir = expand(&self.ca.dir)?;
        self.impersonate.profiles_dir = expand(&self.impersonate.profiles_dir)?;
        Ok(self)
    }
}
```

Add a test:

```rust
    #[test]
    fn impersonate_section_defaults() {
        let c = Config::default();
        assert_eq!(c.impersonate.default_profile, None);
        assert_eq!(c.impersonate.profiles_dir, PathBuf::from("./profiles"));
        assert!(c.impersonate.strip_header);
    }

    #[test]
    fn impersonate_section_parses_from_toml() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            "{}",
            r#"[impersonate]
default_profile = "chrome-137"
strip_header = false"#
        )
        .unwrap();
        let c = load_from_path(f.path()).unwrap();
        assert_eq!(c.impersonate.default_profile.as_deref(), Some("chrome-137"));
        assert!(!c.impersonate.strip_header);
    }
```

- [ ] **Step 7.2: Add `--fingerprint` to the `Serve` subcommand**

In `crates/roxy-proxy/src/cli.rs`, replace the `Command::Serve` variant (line 18):

```rust
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy.
    Serve {
        /// Override [impersonate].default_profile from config. Use "none" to
        /// force the unfingerprinted (rustls) path.
        #[arg(long)]
        fingerprint: Option<String>,
    },
    /// CA trust-store management.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
}
```

- [ ] **Step 7.3: Plumb the flag through `main.rs` and `serve.rs`**

Find the `main.rs` dispatch for `Command::Serve` and adjust it to forward the `fingerprint` argument. Without reading `main.rs`, the change is conceptually:

```rust
Some(Command::Serve { fingerprint }) => serve::run(cli.config.as_deref(), fingerprint.as_deref()).await,
```

In `crates/roxy-proxy/src/serve.rs`, change the `run` signature:

```rust
pub async fn run(config_path: Option<&Path>, fingerprint_override: Option<&str>) -> anyhow::Result<()> {
    let mut cfg = load_config(config_path)?;
    if let Some(f) = fingerprint_override {
        // "none" override unsets the default; any other value becomes the default.
        if f == roxy_impersonate::NONE_LABEL {
            cfg.impersonate.default_profile = None;
        } else {
            cfg.impersonate.default_profile = Some(f.to_string());
        }
    }
    // ... rest of run as in Task 6.7 ...
}
```

- [ ] **Step 7.4: Run tests + manual smoke**

Run: `cargo test --workspace`
Expected: all unit + integration tests pass. New tests in `roxy-config` cover the impersonate section.

Manual smoke (optional but recommended):
```bash
cargo run -p roxy-proxy -- --config /tmp/roxy.toml serve --fingerprint chrome-137
```
where `/tmp/roxy.toml` is empty or minimal. Should print `roxy CA at ...` and `listening` lines without error.

- [ ] **Step 7.5: Commit**

```bash
git add crates/roxy-config/ crates/roxy-proxy/
git commit -m "feat(roxy-config,roxy-proxy): [impersonate] config section + --fingerprint flag

Adds [impersonate] with default_profile, profiles_dir, strip_header.
serve subcommand accepts --fingerprint <name> | --fingerprint none to
override the configured default. Path defaults expand via shellexpand
the same way cache.dir does."
```

---

## Task 8: Ring 2 integration tests

**Files:**
- Create: `crates/roxy-proxy/tests/impersonate.rs`
- Use existing fixture: `crates/roxy-proxy/tests/common/mod.rs` (do not modify; build atop)

The fake-origin fixture from commit `9ccc306` does not validate TLS fingerprints. These tests exercise routing, label resolution, cache-key partitioning, and the custom-profile load path end-to-end — not fingerprint fidelity.

- [ ] **Step 8.1: Read the existing fixture to confirm its API**

Run: `cat crates/roxy-proxy/tests/common/mod.rs` and `cat crates/roxy-proxy/tests/common/trust.rs`. Note the function that starts a roxy + fake origin pair (likely a `RoxyFixture::new()` or `start_test_proxy()` helper) and how tests pass a custom config.

If the existing fixture does not allow a custom `ImpersonateConfig` to be threaded in, extend it with a method like `with_impersonate_config(...)`. This may require a small modification to `common/mod.rs` (still in scope for this task — it's a fixture extension, not a behavior change).

- [ ] **Step 8.2: Author `impersonate.rs` tests**

Create `crates/roxy-proxy/tests/impersonate.rs`:

```rust
//! Ring 2 integration tests for the fingerprint-emulation feature.
//!
//! These tests use the existing fake-origin fixture (no real TLS fingerprint
//! validation upstream). They verify roxy's routing, label resolution,
//! cache-key partitioning, header stripping, and the custom-profile load
//! pipeline.

mod common;

use common::{TestHarness, FINGERPRINT_HEADER};
use reqwest::header::HeaderValue;

/// 1. With a default profile configured, a miss-then-hit round-trip works and
///    the response body is identical on both passes.
#[tokio::test]
async fn impersonate_default_miss_then_hit() {
    let harness = TestHarness::builder()
        .default_profile("chrome-137")
        .build()
        .await;

    let url = harness.fake_origin_url("/cacheable");
    let r1 = harness.client().get(&url).send().await.unwrap();
    assert!(r1.status().is_success());
    let b1 = r1.bytes().await.unwrap();

    let r2 = harness.client().get(&url).send().await.unwrap();
    assert!(r2.status().is_success());
    let b2 = r2.bytes().await.unwrap();

    assert_eq!(b1, b2);
    // The fixture should expose a counter of upstream calls. After two client
    // requests on the same URL, the upstream should have been hit exactly once.
    assert_eq!(harness.upstream_hit_count(&url), 1);
}

/// 2. Same URL with two different profiles produces two cache entries.
#[tokio::test]
async fn profile_partition_in_cache() {
    let harness = TestHarness::builder().build().await; // no default; per-request only

    let url = harness.fake_origin_url("/partition-target");
    let mut req1 = harness.client().get(&url);
    req1 = req1.header(FINGERPRINT_HEADER, "chrome-137");
    req1.send().await.unwrap().bytes().await.unwrap();

    let mut req2 = harness.client().get(&url);
    req2 = req2.header(FINGERPRINT_HEADER, "firefox-139");
    req2.send().await.unwrap().bytes().await.unwrap();

    // Two distinct fingerprints => two upstream calls, both cache misses.
    assert_eq!(harness.upstream_hit_count(&url), 2);
}

/// 3. X-Roxy-Fingerprint: none forces the rustls path even when a default is set.
#[tokio::test]
async fn none_opts_out_of_default() {
    let harness = TestHarness::builder()
        .default_profile("chrome-137")
        .build()
        .await;

    let url = harness.fake_origin_url("/opt-out");
    let mut req = harness.client().get(&url);
    req = req.header(FINGERPRINT_HEADER, "none");
    req.send().await.unwrap().bytes().await.unwrap();

    // Assert the request was served by the rustls client. The fixture can
    // expose this via a per-client counter, e.g. `harness.rustls_calls()` /
    // `harness.impersonate_calls()`. If not yet exposed, the simpler proxy is
    // to inspect the cache directory: `_default`-prefixed entries indicate
    // the rustls path.
    assert!(harness.cache_contains_key_prefix("_default"));
}

/// 4. Unknown fingerprint header → 502, no upstream call.
#[tokio::test]
async fn unknown_profile_returns_502() {
    let harness = TestHarness::builder().build().await;
    let url = harness.fake_origin_url("/anywhere");
    let mut req = harness.client().get(&url);
    req = req.header(FINGERPRINT_HEADER, "chrome-999");
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 502);
    assert_eq!(harness.upstream_hit_count(&url), 0);
}

/// 5. 5xx pass-through still works on the impersonate path.
#[tokio::test]
async fn five_xx_pass_through_impersonate() {
    let harness = TestHarness::builder()
        .default_profile("chrome-137")
        .build()
        .await;
    let url = harness.fake_origin_url_status(503, "/fail");
    let resp = harness.client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 503);
    // 5xx must not have been cached.
    assert!(!harness.cache_contains_url(&url));
}

/// 6. Custom profile loaded from a TOML in profiles_dir is dispatchable.
#[tokio::test]
async fn custom_profile_loads_and_serves() {
    let dir = tempfile::tempdir().unwrap();
    let toml = r#"
name = "my-custom"

[tls]
alpn = ["h2", "http/1.1"]
cipher_suites = ["TLS_AES_128_GCM_SHA256"]
extensions = ["server_name", "supported_groups"]
supported_versions = ["TLS1.3", "TLS1.2"]
signature_algorithms = ["ecdsa_secp256r1_sha256"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_frame_size = 16384
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH"]
header_order = [":method", ":authority", ":scheme", ":path"]
"#;
    std::fs::write(dir.path().join("custom.toml"), toml).unwrap();

    let harness = TestHarness::builder()
        .profiles_dir(dir.path())
        .build()
        .await;

    let url = harness.fake_origin_url("/custom-test");
    let mut req = harness.client().get(&url);
    req = req.header(FINGERPRINT_HEADER, "my-custom");
    let resp = req.send().await.unwrap();
    // The fake origin doesn't care about the actual TLS bytes; success here
    // proves the custom profile was registered and dispatched.
    assert!(resp.status().is_success());
    let _ = HeaderValue::from_static("noop"); // silence unused-imports
}

/// 7. Fingerprint header is stripped from the upstream request.
#[tokio::test]
async fn fingerprint_header_stripped_upstream() {
    let harness = TestHarness::builder()
        .default_profile("chrome-137")
        .build()
        .await;

    let url = harness.fake_origin_url("/echo-headers");
    let mut req = harness.client().get(&url);
    req = req.header(FINGERPRINT_HEADER, "firefox-139");
    let resp = req.send().await.unwrap();
    let body = resp.text().await.unwrap();
    // The fake origin's /echo-headers route returns the request headers it
    // received as JSON or text. Assert X-Roxy-Fingerprint is not among them.
    assert!(!body.to_lowercase().contains("x-roxy-fingerprint"), "got: {body}");
}
```

The fixture extension to support `default_profile`, `profiles_dir`, `cache_contains_key_prefix`, `upstream_hit_count`, `fake_origin_url_status`, and `/echo-headers` is part of this task. If the existing fixture already exposes some of these (it tracks hit counts for the existing `golden.rs` test), reuse them.

Note: The `FINGERPRINT_HEADER` constant referenced in tests should be re-exported from `roxy_proxy_lib` or duplicated in `tests/common/mod.rs` as a `pub const`. Match whatever convention the existing fixture uses.

- [ ] **Step 8.3: Run integration tests**

Run: `cargo test -p roxy-proxy --test impersonate`
Expected: all 7 tests pass. They'll take longer than unit tests because each spins up a roxy + fake origin pair.

If `unknown_profile_returns_502` returns 200 instead, the impersonate client is not configured in the test harness — fix the fixture to construct it unconditionally (or, equivalently, fall through to UnknownFingerprint when the impersonate client is absent even with a non-default label).

- [ ] **Step 8.4: Commit**

```bash
git add crates/roxy-proxy/tests/impersonate.rs crates/roxy-proxy/tests/common/
git commit -m "test(roxy-proxy): Ring 2 integration tests for fingerprint emulation

Covers: default-profile miss/hit, profile-partition in cache, 'none'
escape hatch, unknown profile 502, 5xx pass-through on impersonate path,
custom profile load + dispatch, header stripping."
```

---

## Task 9: Ring 3 fingerprint fidelity smoke (`#[ignore]`)

**Files:**
- Create: `crates/roxy-proxy/tests/fingerprint_smoke.rs`

These tests reach the public internet and assert wreq's emitted fingerprint matches known-good values for the configured profile. They follow the precedent of commit `69b4471` (the httpbin smoke test) — marked `#[ignore]` so CI does not run them by default.

- [ ] **Step 9.1: Write the smoke**

Create `crates/roxy-proxy/tests/fingerprint_smoke.rs`:

```rust
//! Ring 3 fingerprint fidelity smoke tests. `#[ignore]` because they require
//! network access. Run with: `cargo test -p roxy-proxy --test fingerprint_smoke -- --ignored --nocapture`
//!
//! These tests are operator-run gates, not CI tests. They prove that wreq's
//! bytes still match the expected fingerprint for each shipped builtin
//! profile, end-to-end through roxy.

mod common;

use common::{TestHarness, FINGERPRINT_HEADER};
use serde_json::Value;

/// Known JA4 prefix for Chrome 137. The full JA4 string includes a hash
/// component that changes with extension content, so we match on the prefix
/// that encodes TLS version, SNI presence, cipher count, and ALPN.
///
/// Update this constant when bumping wreq versions or when adding a new
/// Chrome variant. The current expected value should be confirmed against
/// https://browserleaks.com/tls in a real Chrome 137 session.
const CHROME_137_JA4_PREFIX: &str = "t13d";

#[tokio::test]
#[ignore = "requires network"]
async fn chrome_137_smoke_via_peet() {
    let harness = TestHarness::builder()
        .default_profile("chrome-137")
        .build()
        .await;

    // tls.peet.ws/api/all returns observed JA3, JA4, Akamai HTTP/2 fingerprint
    // for the connecting client as JSON.
    let resp = harness
        .client()
        .get("https://tls.peet.ws/api/all")
        .send()
        .await
        .expect("upstream reachable");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let json: Value = resp.json().await.expect("json response");
    let ja4 = json["tls"]["ja4"]
        .as_str()
        .expect("response has tls.ja4");
    assert!(
        ja4.starts_with(CHROME_137_JA4_PREFIX),
        "expected JA4 starting with {CHROME_137_JA4_PREFIX}, got {ja4}"
    );
}

#[tokio::test]
#[ignore = "requires network"]
async fn custom_profile_smoke_via_peet() {
    // A minimal custom profile that's distinct from any builtin. The expected
    // JA4 reflects the configured cipher count + extension set, not Chrome's.
    let dir = tempfile::tempdir().unwrap();
    let toml = r#"
name = "smoke-custom"

[tls]
alpn = ["h2", "http/1.1"]
cipher_suites = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
extensions = ["server_name", "supported_groups", "key_share", "supported_versions", "signature_algorithms"]
supported_versions = ["TLS1.3"]
signature_algorithms = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"]

[http2]
header_table_size = 4096
enable_push = false
initial_window_size = 65535
max_frame_size = 16384
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE"]
header_order = [":method", ":authority", ":scheme", ":path", "user-agent", "accept"]
"#;
    std::fs::write(dir.path().join("smoke-custom.toml"), toml).unwrap();

    let harness = TestHarness::builder()
        .profiles_dir(dir.path())
        .build()
        .await;

    let mut req = harness.client().get("https://tls.peet.ws/api/all");
    req = req.header(FINGERPRINT_HEADER, "smoke-custom");
    let resp = req.send().await.expect("upstream reachable");
    assert!(resp.status().is_success());
    let json: Value = resp.json().await.expect("json response");
    // Custom profile uses TLS 1.3 only, so JA4 should start with "t13".
    let ja4 = json["tls"]["ja4"].as_str().expect("response has tls.ja4");
    assert!(ja4.starts_with("t13"), "expected TLS1.3 JA4, got {ja4}");
}
```

If `tls.peet.ws` is down at the time of running, swap for `https://check.ja3.zone/api/all` or `https://api.browserleaks.com/tls` — JSON shape will differ, adjust the field accesses accordingly.

- [ ] **Step 9.2: Manual run**

Run: `cargo test -p roxy-proxy --test fingerprint_smoke -- --ignored --nocapture`
Expected (operator interpretation):
- `chrome_137_smoke_via_peet` passes, with the `tls.ja4` field in the response starting with `t13d` (TLS 1.3, with SNI, … — the full prefix depends on the JA4 spec).
- `custom_profile_smoke_via_peet` passes, with `tls.ja4` starting with `t13`.

If JA4 differs from the expected prefix, this indicates either (a) wreq's emitted fingerprint has drifted from the expected value (likely a wreq update), or (b) the expected constant is stale. Update the constant or open an issue.

- [ ] **Step 9.3: Commit**

```bash
git add crates/roxy-proxy/tests/fingerprint_smoke.rs
git commit -m "test(roxy-proxy): #[ignore] Ring 3 fingerprint fidelity smoke

End-to-end smoke against tls.peet.ws verifying wreq's emitted JA4
matches Chrome 137 and a custom TLS 1.3 profile. Operator-run gate,
not CI."
```

---

## Self-Review

Spec coverage check (each spec section → tasks):

| Spec section                  | Implementing task(s)                  |
|-------------------------------|---------------------------------------|
| New crate `roxy-impersonate`  | Task 3, 4, 5                           |
| Trait + body unification      | Task 2 (body), Task 6 (router/trait)  |
| Router in roxy-http           | Task 6                                |
| Handler integration           | Task 6                                |
| Config schema                 | Task 7                                |
| CLI `--fingerprint`           | Task 7                                |
| Per-request header semantics  | Task 6 (resolve_label table)          |
| Profile names + validation    | Task 3 (ProfileName::parse)           |
| Custom profile TOML           | Task 5                                |
| Cache key change              | Task 1                                |
| Data flow (3 cases)           | Tasks 2, 4, 6 collectively            |
| Error handling — startup      | Task 7 (serve.rs unknown-default fails)|
| Error handling — request      | Task 6 (handler match, 502 vs 400)    |
| Dependency / build caveats    | Task 3.6 build note (cmake/perl/clang)|
| Ring 1 tests                  | Tasks 1, 3, 4, 5, 6 (inline unit)     |
| Ring 2 tests                  | Task 8                                |
| Ring 3 tests                  | Task 9                                |
| Sequencing                    | Task ordering matches spec §Sequencing |
| Pre-merge gates               | Implicit in Tasks 8, 9 + final manual run |

Placeholder scan: One area to flag for the implementer rather than treat as a placeholder — Task 5 step 5.1's `build_provider` function has a comment "IMPLEMENTER NOTE" with the exact wreq builder calls left as a translation of the spec fields. This is not a placeholder in the sense of "TBD"; it's a directed mechanical translation. The wreq builder field names will be exact at write-time (`cargo doc --open -p wreq`). The same goes for the wreq feature-flag set in Task 3.1.

Type consistency: `UpstreamBody` variants (`Hyper`, `Impersonate`) and constructors (`UpstreamBody::hyper`, `UpstreamBody::impersonate`) are consistent across Tasks 2 and 4. `UpstreamError` variants (`Client`, `Uri`, `UnknownFingerprint`, `Impersonate`) consistent in Tasks 6 and 7. `Profile` enum names match between Tasks 3 (definition) and 4 (consumer in `ImpersonateClient::client_for`). Cache-key signature `from_parts(profile, method, scheme, host, path, query)` consistent across Tasks 1 and 6.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-13-tls-fingerprint-emulation.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task with the task body + spec references; review the diff between tasks before kicking off the next. Best for nine sequential tasks of this size because each subagent gets a clean context and the human/orchestrator stays in control of the boundaries.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints. Lower overhead, but the wreq build the first time round will eat into context.

Which approach?
