# Plain HTTP Proxy Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make roxy accept absolute-form HTTP requests (e.g. `GET http://example.com/ HTTP/1.1`) on the same listener port as the existing CONNECT/HTTPS path, forwarding them through the existing handler/router/cache pipeline.

**Architecture:** Peek-based dispatch via `tokio::TcpStream::peek` in `accept.rs` branches CONNECT to MITM, everything else to a new plain-HTTP serve loop. The `Handler` is refactored so `handle_tunneled` (existing CONNECT path) and a new `handle_plain` share a single `handle_inner(label, authority, scheme, req)` body. The cache-key helper gains a scheme parameter so HTTP and HTTPS naturally separate in the cache. Plain HTTP strict-ignores `X-Roxy-Fingerprint` and forces `_default` (rustls) routing.

**Tech Stack:** Rust workspace, tokio (`TcpStream::peek` = MSG_PEEK), hyper + `hyper_util::server::conn::auto`, axum (origin fixtures), reqwest (test client).

**Spec:** `docs/superpowers/specs/2026-05-13-plain-http-proxy-design.md`
**Issue:** `roxy-o69` (already `in_progress`).

---

## File Structure

- **Modify:** `crates/roxy-proxy/src/handler.rs`
  - Refactor `Handler::handle` → `handle_tunneled` + private `handle_inner(label, authority, scheme, req)`.
  - Parameterize `build_cache_key_and_warn` with `scheme: &str`.
  - Add `extract_plain_target` private helper.
  - Add `Handler::handle_plain`.
  - Add three unit tests covering scheme parameterization and plain-target extraction.
- **Modify:** `crates/roxy-http/src/server.rs`
  - Add `serve_http_plain` helper.
- **Modify:** `crates/roxy-http/src/lib.rs`
  - Re-export `serve_http_plain`.
- **Modify:** `crates/roxy-http/src/accept.rs`
  - Extend `ConnHandler` trait with `handle_plain(&self, stream: TcpStream)`.
  - Replace `read_connect` call site with peek-based dispatch.
- **Modify:** `crates/roxy-proxy/src/serve.rs`
  - `ProxyConnHandler::handle` renamed to `handle_tunneled` per trait.
  - `ProxyConnHandler::handle_plain` implementation.
- **Create:** `crates/roxy-proxy/tests/http_plain.rs`
  - End-to-end integration test (axum plain origin + roxy + reqwest proxy client).

No new crates, no new dependencies.

---

## Task 1: Refactor `Handler` for scheme parameterization

**Files:**
- Modify: `crates/roxy-proxy/src/handler.rs`
- Modify: `crates/roxy-proxy/src/serve.rs`

Pure refactor. After this task the existing CONNECT/HTTPS behavior is unchanged; the only change is internal structure. Sets up the seam that Task 2 will plug into.

- [ ] **Step 1: Extract `handle_inner` and rename `handle` to `handle_tunneled`**

In `crates/roxy-proxy/src/handler.rs`, change the `impl Handler` block. The current `pub async fn handle(&self, authority: String, mut req: Request<hyper::body::Incoming>) -> Result<…>` becomes two functions: a thin public `handle_tunneled` that does label resolution + fingerprint-header stripping (current lines 36-56), then calls a private `handle_inner(label, authority, scheme, req)` containing everything from line 58 onward.

The new function signature for `handle_inner`:

```rust
async fn handle_inner(
    &self,
    label: String,
    authority: String,
    scheme: &str,
    mut req: http::Request<hyper::body::Incoming>,
) -> Result<http::Response<BoxBody>, std::convert::Infallible> {
    // 3. Cache key.
    let key = build_cache_key_and_warn(&req, &label, scheme, &authority);
    // ...rest of existing body unchanged, except line 65 below
}
```

The URI rebuild at the current `handler.rs:65` stays as written (`req.uri().scheme_str().unwrap_or("https")`) — the fallback is only hit for tunneled HTTPS requests where the inner request-target has no scheme. For the future plain path, the URI carries `http://` explicitly so the fallback isn't reached.

The new `handle_tunneled`:

```rust
pub async fn handle_tunneled(
    &self,
    authority: String,
    mut req: http::Request<hyper::body::Incoming>,
) -> Result<http::Response<BoxBody>, std::convert::Infallible> {
    // 1. Resolve profile label.
    let label = match resolve_label(req.headers(), self.default_profile.as_deref()) {
        Ok(l) => l,
        Err(LabelError::MultipleHeaders) => {
            return Ok(simple(
                http::StatusCode::BAD_REQUEST,
                "roxy: X-Roxy-Fingerprint must be set at most once",
            ));
        }
        Err(LabelError::BadValue(_)) => {
            return Ok(simple(
                http::StatusCode::BAD_REQUEST,
                "roxy: X-Roxy-Fingerprint value must match ^[a-z0-9][a-z0-9-]*$",
            ));
        }
    };

    // 2. Strip header before forwarding upstream (config-gated).
    if self.strip_fingerprint_header {
        req.headers_mut().remove(FINGERPRINT_HEADER);
    }

    self.handle_inner(label, authority, "https", req).await
}
```

- [ ] **Step 2: Parameterize `build_cache_key_and_warn` with scheme**

In `crates/roxy-proxy/src/handler.rs`, change the helper from:

```rust
fn build_cache_key_and_warn<B>(req: &Request<B>, label: &str, authority: &str) -> CacheKey {
    let host_for_key = authority.to_ascii_lowercase();
    let key = CacheKey::from_parts(
        label,
        req.method().as_str(),
        "https",
        &host_for_key,
        req.uri().path(),
        req.uri().query(),
    );
    // ...mismatch-warning logic unchanged...
}
```

to:

```rust
fn build_cache_key_and_warn<B>(
    req: &Request<B>,
    label: &str,
    scheme: &str,
    authority: &str,
) -> CacheKey {
    let host_for_key = authority.to_ascii_lowercase();
    let key = CacheKey::from_parts(
        label,
        req.method().as_str(),
        scheme,
        &host_for_key,
        req.uri().path(),
        req.uri().query(),
    );
    // ...mismatch-warning logic unchanged...
}
```

- [ ] **Step 3: Update existing `key_tests` to pass scheme**

In `crates/roxy-proxy/src/handler.rs`'s `mod key_tests`, update the four existing calls to `build_cache_key_and_warn` to pass `"https"` explicitly:

```rust
// In cache_key_uses_connect_authority:
let key = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");

// In host_mismatch_emits_warning:
let _ = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");

// In matching_host_does_not_warn:
let _ = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");

// In absolute_form_uri_matching_connect_authority_does_not_warn:
let _ = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");
```

- [ ] **Step 4: Add a regression test for scheme parameterization**

Append inside `mod key_tests`, after the existing tests:

```rust
    #[test]
    fn cache_key_uses_http_scheme_differs_from_https() {
        let req = Request::get("http://bank.com/api")
            .body(())
            .unwrap();
        let http_key = build_cache_key_and_warn(&req, "p", "http", "bank.com:80");
        let https_key = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");
        assert_ne!(http_key, https_key, "scheme must participate in the cache key");
    }
```

- [ ] **Step 5: Update `ProxyConnHandler` to call the renamed method**

In `crates/roxy-proxy/src/serve.rs`, change the closure inside `ProxyConnHandler::handle` (lines 140-152) to call `inner.handle_tunneled` instead of `inner.handle`:

```rust
async fn handle(
    &self,
    authority: String,
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) {
    let inner = self.inner.clone();
    let authority_clone = authority.clone();
    roxy_http::serve_tls(tls, move |req| {
        let inner = inner.clone();
        let authority = authority_clone.clone();
        async move { inner.handle_tunneled(authority, req).await }
    })
    .await;
}
```

(Only the method name changes; everything else is identical.)

- [ ] **Step 6: Run workspace build and tests**

Run: `cargo build --workspace`
Expected: clean.

Run: `cargo test --workspace`
Expected: all tests pass (including the new `cache_key_uses_http_scheme_differs_from_https`).

- [ ] **Step 7: Run clippy on both views**

Run: `cargo clippy --workspace -- -D warnings`
Expected: clean.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 8: Run rustfmt**

Run: `cargo fmt --all`
Expected: clean or trivial fixes.

- [ ] **Step 9: Commit**

```bash
git add crates/roxy-proxy/src/handler.rs crates/roxy-proxy/src/serve.rs
git commit -m "$(cat <<'EOF'
refactor(roxy-proxy): extract Handler::handle_inner + parameterize cache-key scheme

Pure refactor in service of plain-HTTP proxy support (roxy-o69).
Renames Handler::handle → handle_tunneled (still does label resolution
and fingerprint-header stripping for the CONNECT/HTTPS path), and
extracts the body into a private handle_inner(label, authority, scheme, req).
build_cache_key_and_warn gains a `scheme: &str` parameter so HTTP and
HTTPS entries naturally separate in the cache.

Existing CONNECT/HTTPS behavior is unchanged; the four existing
key_tests pass "https" explicitly. New cache_key_uses_http_scheme_differs_from_https
test guards the parameterization.

Part of roxy-o69. Follow-up commits add handle_plain and the plain-HTTP
listener path.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add `Handler::handle_plain` entry point

**Files:**
- Modify: `crates/roxy-proxy/src/handler.rs`

Adds the public method that processes absolute-form HTTP requests. The method extracts authority/scheme from the request URI, returns 400 if absent, strips `X-Roxy-Fingerprint`, and dispatches via `handle_inner` with `DEFAULT_LABEL`.

Pure-helper extraction makes unit tests cheap; the full end-to-end is covered by the integration test in Task 5.

- [ ] **Step 1: Add `extract_plain_target` private helper**

In `crates/roxy-proxy/src/handler.rs`, add this free function near the other private helpers (between `authority_matches` and `build_cache_key_and_warn`):

```rust
/// Extract the (authority, scheme) pair from an absolute-form request URI.
/// Returns `Err` with a static message when the URI has no authority
/// (e.g. path-only request-target, which is invalid for a forward proxy).
fn extract_plain_target(uri: &http::Uri) -> Result<(String, String), &'static str> {
    let authority = uri
        .authority()
        .ok_or("missing absolute-form authority")?
        .as_str()
        .to_string();
    let scheme = uri.scheme_str().unwrap_or("http").to_string();
    Ok((authority, scheme))
}
```

- [ ] **Step 2: Add unit tests for `extract_plain_target`**

Append inside `mod key_tests` (after the test added in Task 1):

```rust
    #[test]
    fn extract_plain_target_absolute_form_http() {
        let uri: http::Uri = "http://example.com/path".parse().unwrap();
        let (authority, scheme) = extract_plain_target(&uri).unwrap();
        assert_eq!(authority, "example.com");
        assert_eq!(scheme, "http");
    }

    #[test]
    fn extract_plain_target_preserves_port() {
        let uri: http::Uri = "http://example.com:8080/path".parse().unwrap();
        let (authority, _) = extract_plain_target(&uri).unwrap();
        assert_eq!(authority, "example.com:8080");
    }

    #[test]
    fn extract_plain_target_path_only_errors() {
        let uri: http::Uri = "/path".parse().unwrap();
        let err = extract_plain_target(&uri).unwrap_err();
        assert!(err.contains("authority"), "got: {err}");
    }
```

- [ ] **Step 3: Run the new tests to verify they pass**

Run: `cargo test -p roxy-proxy --lib key_tests::extract_plain_target_`
Expected: 3 passing tests.

- [ ] **Step 4: Add `Handler::handle_plain` method**

In `crates/roxy-proxy/src/handler.rs`, add this public method inside `impl<C: Cache + 'static> Handler<C>`, immediately after `handle_tunneled`:

```rust
pub async fn handle_plain(
    &self,
    mut req: http::Request<hyper::body::Incoming>,
) -> Result<http::Response<BoxBody>, std::convert::Infallible> {
    // 1. Extract the absolute-form target (authority + scheme).
    let (authority, scheme) = match extract_plain_target(req.uri()) {
        Ok(t) => t,
        Err(_) => {
            return Ok(simple(
                http::StatusCode::BAD_REQUEST,
                "roxy: HTTP request missing absolute-form URI",
            ));
        }
    };

    // 2. Plain HTTP strict-ignores X-Roxy-Fingerprint. Strip it
    //    unconditionally; never honor it. See spec, "Non-goals".
    req.headers_mut().remove(FINGERPRINT_HEADER);

    // 3. Force routing through the rustls (_default) path. Fingerprint
    //    has no meaningful effect over plain HTTP and is documented
    //    as such.
    let label = roxy_impersonate::DEFAULT_LABEL.to_string();

    self.handle_inner(label, authority, &scheme, req).await
}
```

- [ ] **Step 5: Run workspace build and tests**

Run: `cargo build --workspace`
Expected: clean.

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 6: Run clippy on both views**

Run: `cargo clippy --workspace -- -D warnings`
Expected: clean.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/roxy-proxy/src/handler.rs
git commit -m "$(cat <<'EOF'
feat(roxy-proxy): Handler::handle_plain for absolute-form HTTP requests

Adds the entry point for plain-HTTP forward proxying. Extracts
authority + scheme from the absolute-form URI, returns 400 on
path-only request-targets, strips X-Roxy-Fingerprint (plain HTTP
documented as strict-ignore for fingerprint), and dispatches via
handle_inner with the _default label.

Part of roxy-o69. Follow-up commit wires this in via the listener
dispatch path.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Add `serve_http_plain` + extend `ConnHandler` trait

**Files:**
- Modify: `crates/roxy-http/src/server.rs`
- Modify: `crates/roxy-http/src/lib.rs`
- Modify: `crates/roxy-http/src/accept.rs`
- Modify: `crates/roxy-proxy/src/serve.rs`

Adds the plain-TCP serve helper, extends the trait, implements the new method on `ProxyConnHandler`. After this task the trait is fully extended but nothing yet dispatches to the new method — Task 4 wires the listener.

- [ ] **Step 1: Add `serve_http_plain` to `crates/roxy-http/src/server.rs`**

Append to the bottom of `server.rs`:

```rust
pub async fn serve_http_plain<F, Fut>(stream: tokio::net::TcpStream, handler: F)
where
    F: Fn(http::Request<hyper::body::Incoming>) -> Fut + Clone + Send + 'static,
    Fut: std::future::Future<
            Output = Result<http::Response<BoxBody>, std::convert::Infallible>,
        > + Send
        + 'static,
{
    let io = TokioIo::new(stream);
    let svc = hyper::service::service_fn(move |req| {
        let handler = handler.clone();
        async move { handler(req).await }
    });
    let _ = auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, svc)
        .await;
}
```

The `serve_tls` function above already imports `auto`, `TokioExecutor`, `TokioIo`, `BoxBody` — no new imports needed.

- [ ] **Step 2: Re-export from `crates/roxy-http/src/lib.rs`**

Change the `pub use server::…` line:

```rust
pub use server::{serve_http_plain, serve_tls, BoxBody};
```

(Add `serve_http_plain` to the existing export list, keeping alphabetical order.)

- [ ] **Step 3: Extend `ConnHandler` trait in `crates/roxy-http/src/accept.rs`**

Modify the trait definition (currently lines 10-17). Add a new method `handle_plain`:

```rust
#[async_trait::async_trait]
pub trait ConnHandler: Send + Sync {
    async fn handle_tunneled(
        &self,
        authority: String,
        tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    );
    async fn handle_plain(&self, stream: tokio::net::TcpStream);
}
```

Note the existing `handle` method is RENAMED to `handle_tunneled` to match the Handler-level convention from Task 1. No default impl on `handle_plain` — implementers must provide one (only `ProxyConnHandler` today).

- [ ] **Step 4: Update `ProxyConnHandler` in `crates/roxy-proxy/src/serve.rs`**

Rename the existing `handle` method to `handle_tunneled`, and add `handle_plain`:

```rust
#[async_trait::async_trait]
impl<C: Cache + 'static> ConnHandler for ProxyConnHandler<C> {
    async fn handle_tunneled(
        &self,
        authority: String,
        tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) {
        let inner = self.inner.clone();
        let authority_clone = authority.clone();
        roxy_http::serve_tls(tls, move |req| {
            let inner = inner.clone();
            let authority = authority_clone.clone();
            async move { inner.handle_tunneled(authority, req).await }
        })
        .await;
    }

    async fn handle_plain(&self, stream: tokio::net::TcpStream) {
        let inner = self.inner.clone();
        roxy_http::serve_http_plain(stream, move |req| {
            let inner = inner.clone();
            async move { inner.handle_plain(req).await }
        })
        .await;
    }
}
```

- [ ] **Step 5: Run workspace build**

Run: `cargo build --workspace`
Expected: clean. (The `accept::run` function at `accept.rs:59` still calls `handler.handle(...)` — this will become a compile error referencing the renamed method. That's expected; Task 4 fixes it.)

If it fails with `no method named 'handle' found for type 'Handler'` at `accept.rs:59`, that's the expected intermediate state. Proceed to Step 6, but DO NOT commit yet.

Actually wait — since this commit is supposed to compile cleanly, let's fix accept.rs:59 in this same commit instead of leaving a known-broken state. Update the `accept.rs::run` function (around line 59) to use the new trait method:

In `crates/roxy-http/src/accept.rs`, the existing line 59 (inside the accept loop):

```rust
handler.handle(host, tls).await;
```

becomes:

```rust
handler.handle_tunneled(host, tls).await;
```

(Just renaming the trait method call; the actual peek-based dispatch comes in Task 4.)

- [ ] **Step 6: Run the workspace build again**

Run: `cargo build --workspace`
Expected: clean.

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 7: Clippy on both views**

Run: `cargo clippy --workspace -- -D warnings`
Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 8: rustfmt**

Run: `cargo fmt --all`

- [ ] **Step 9: Commit**

```bash
git add crates/roxy-http/src/server.rs crates/roxy-http/src/lib.rs crates/roxy-http/src/accept.rs crates/roxy-proxy/src/serve.rs
git commit -m "$(cat <<'EOF'
feat(roxy-http,roxy-proxy): ConnHandler::handle_plain + serve_http_plain

Extends the ConnHandler trait with a handle_plain(TcpStream) method
for plain-HTTP forward proxying, and adds a serve_http_plain helper
that mirrors serve_tls but on raw TCP (no TLS). ProxyConnHandler
implements the new method by delegating to Handler::handle_plain.

The existing ConnHandler::handle method is renamed to handle_tunneled
to make the CONNECT-vs-plain distinction explicit at the trait level.

No listener-level dispatch yet — accept.rs still always calls
handle_tunneled. Follow-up commit adds peek-based dispatch.

Part of roxy-o69.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Peek-based dispatch in `accept.rs`

**Files:**
- Modify: `crates/roxy-http/src/accept.rs`

Replaces the current `read_connect` call site with a `TcpStream::peek` branch. Plain-HTTP requests now reach `handle_plain`; CONNECT requests follow the existing flow. The unit-level verification is via Task 5's integration test (real bytes through real TCP).

- [ ] **Step 1: Update the per-connection task in `accept.rs::run`**

Replace the body of the `tokio::spawn` block in `crates/roxy-http/src/accept.rs` (currently lines 33-60) with the peek-based branch.

The new code for that block:

```rust
tokio::spawn(async move {
    let mut peek_buf = [0u8; 8];
    let n = match sock.peek(&mut peek_buf).await {
        Ok(n) => n,
        Err(e) => {
            warn!(?peer, error = %e, "peek failed");
            return;
        }
    };
    if n >= 8 && &peek_buf == b"CONNECT " {
        // CONNECT flow: tunneled HTTPS via MITM.
        let host = match read_connect(&mut sock).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                // Shouldn't happen — peek already confirmed CONNECT.
                warn!(?peer, "peek said CONNECT but read_connect returned None");
                return;
            }
            Err(e) => {
                warn!(?peer, error = %e, "read_connect failed");
                return;
            }
        };
        if let Err(e) = write_200(&mut sock).await {
            warn!(?peer, error = %e, "write 200 failed");
            return;
        }
        let acceptor = terminator.acceptor();
        let tls = match acceptor.accept(sock).await {
            Ok(t) => t,
            Err(e) => {
                warn!(?peer, error = %e, "TLS handshake failed");
                return;
            }
        };
        handler.handle_tunneled(host, tls).await;
    } else {
        // Plain HTTP flow: absolute-form HTTP requests, no TLS.
        handler.handle_plain(sock).await;
    }
});
```

The existing top-level imports in this file (`crate::connect::{read_connect, write_200}`, `roxy_mitm::Terminator`, etc.) are already present and unchanged.

- [ ] **Step 2: Run the workspace build**

Run: `cargo build --workspace`
Expected: clean.

- [ ] **Step 3: Run tests**

Run: `cargo test --workspace`
Expected: all existing tests still pass. The integration tests in `crates/roxy-proxy/tests/` use CONNECT, so they exercise the CONNECT branch of the new dispatch.

- [ ] **Step 4: Clippy on both views**

Run: `cargo clippy --workspace -- -D warnings`
Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 5: rustfmt**

Run: `cargo fmt --all`

- [ ] **Step 6: Commit**

```bash
git add crates/roxy-http/src/accept.rs
git commit -m "$(cat <<'EOF'
feat(roxy-http): peek-based CONNECT-vs-HTTP dispatch in accept loop

Replaces the unconditional read_connect call with a TcpStream::peek
branch. If the first 8 bytes spell 'CONNECT ', run the existing MITM
flow. Otherwise hand the un-consumed TCP stream to handle_plain for
absolute-form HTTP proxying. MSG_PEEK keeps the stream intact so the
plain-HTTP path gets the full request.

Existing CONNECT-based integration tests continue to exercise the
CONNECT branch.

Part of roxy-o69.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: End-to-end integration test for plain HTTP proxy

**Files:**
- Create: `crates/roxy-proxy/tests/http_plain.rs`

Spawns a plain-HTTP axum origin (distinct from the existing HTTPS fixture in `tests/common/mod.rs`), spawns roxy, sends a request through `reqwest` configured with `.proxy(Proxy::http(roxy_addr))`, and verifies miss-then-hit cache behavior.

The new test file is self-contained — it does not extend the existing `tests/common/mod.rs` fixture to keep the change focused. If more plain-HTTP tests appear later, factor shared setup at that point.

- [ ] **Step 1: Create `crates/roxy-proxy/tests/http_plain.rs`**

Create the file with the following content:

```rust
#![allow(clippy::unwrap_used)]

//! End-to-end integration test for plain HTTP forward-proxying.
//!
//! Spawns a plain-HTTP axum origin and roxy on random ports, then sends
//! a request through reqwest configured with an HTTP proxy. Verifies
//! status/body and miss-then-hit cache behavior.

use axum::{extract::State, routing::get, Router};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

#[derive(Clone, Default)]
struct OriginState {
    hits: Arc<Mutex<usize>>,
}

async fn spawn_origin() -> (SocketAddr, Arc<Mutex<usize>>) {
    let state = OriginState::default();
    let hits = state.hits.clone();
    let app = Router::new()
        .route(
            "/cacheable",
            get(|State(s): State<OriginState>| async move {
                *s.hits.lock().unwrap() += 1;
                "plain-cacheable-body"
            }),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, hits)
}

async fn spawn_roxy() -> (SocketAddr, TempDir) {
    // rustls global provider (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = tempfile::tempdir().unwrap();

    // Bind a free port then drop the listener; roxy rebinds it.
    let scratch = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let roxy_addr: SocketAddr = scratch.local_addr().unwrap();
    drop(scratch);

    let cfg_path = tmp.path().join("roxy.toml");
    let cfg_text = format!(
        r#"
listen = "{roxy_addr}"
[cache]
dir = "{}"
default_ttl_seconds = 3600
[ca]
dir = "{}"
[log]
level = "warn"
"#,
        tmp.path().join("cache").display(),
        tmp.path().join("ca").display(),
    );
    std::fs::write(&cfg_path, cfg_text).unwrap();

    let cfg_path_for_task = cfg_path.clone();
    tokio::spawn(async move {
        roxy_proxy_lib::serve::run(Some(&cfg_path_for_task), None).await
    });

    // Wait until the proxy listener accepts connections.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(roxy_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (roxy_addr, tmp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_request_is_proxied_and_cached() {
    let (origin_addr, hits) = spawn_origin().await;
    let (roxy_addr, _tmp) = spawn_roxy().await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{roxy_addr}")).unwrap())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/cacheable", origin_addr.port());

    // First request — origin should be hit once.
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "plain-cacheable-body");
    assert_eq!(*hits.lock().unwrap(), 1, "origin should be hit once on miss");

    // Second request — must hit cache, origin count unchanged.
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "plain-cacheable-body");
    assert_eq!(
        *hits.lock().unwrap(),
        1,
        "second request must be served from cache (origin hit count must not increment)"
    );
}
```

Note the use of `tokio::net::TcpListener::bind` (async) for the origin and `std::net::TcpListener::bind` (sync) for the roxy address scratch — this matches the existing fixture pattern in `tests/common/mod.rs` where the roxy port is picked sync then re-bound by the server.

- [ ] **Step 2: Run the new test**

Run: `cargo test -p roxy-proxy --test http_plain`
Expected: 1 passing test.

If `axum::serve` is unavailable in the version of axum used in dev-deps (older axum may need `axum_server` or a different invocation), inspect the actual axum version with `cargo tree -p axum` and adapt the spawn to match the existing fixture's pattern. The existing fixture at `tests/common/mod.rs:274-279` uses `axum_server::from_tcp_rustls(...)` for HTTPS; the plain-HTTP equivalent is `axum::serve(listener, app)` which exists since axum 0.7.

- [ ] **Step 3: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: all tests pass, including existing CONNECT/HTTPS tests and the new plain-HTTP test.

- [ ] **Step 4: Clippy on both views**

Run: `cargo clippy --workspace -- -D warnings`
Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 5: rustfmt**

Run: `cargo fmt --all`

- [ ] **Step 6: Commit**

```bash
git add crates/roxy-proxy/tests/http_plain.rs
git commit -m "$(cat <<'EOF'
test(roxy-proxy): end-to-end plain HTTP proxy + cache hit (roxy-o69)

Spawns a plain-HTTP axum origin and roxy on random ports, sends a
request through reqwest configured with an HTTP proxy, verifies
miss-then-hit cache behavior. Distinct from the existing HTTPS/MITM
fixture in tests/common/mod.rs.

Closes roxy-o69 once verification passes.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Verification, close issue, push

- [ ] **Step 1: Release build verification**

Run: `cargo build --release --workspace`
Expected: clean (production build still compiles without test-utils).

- [ ] **Step 2: Full workspace tests**

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 3: Both clippy views**

Run: `cargo clippy --workspace -- -D warnings`
Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: both clean.

- [ ] **Step 4: rustfmt check**

Run: `cargo fmt --all -- --check`
Expected: no output.

- [ ] **Step 5: Close beads issue**

Run:
```bash
bd close roxy-o69 --reason="Plain HTTP proxy support implemented. Peek-based dispatch in accept.rs; Handler::handle_plain reuses handle_inner with scheme parameterization. Strict-ignore fingerprint on plain HTTP. End-to-end test in crates/roxy-proxy/tests/http_plain.rs."
```
Expected: `✓ Closed roxy-o69`.

- [ ] **Step 6: Push to remote**

Run: `git push`
Expected: push succeeds.

- [ ] **Step 7: Confirm clean state**

Run: `git status && bd ready | head -3`
Expected: working tree clean (modulo untracked `.claude/` and `target/`); `bd ready` no longer lists `roxy-o69`.

---

## Verification Summary

After all six tasks:

- `grep -rn "handler\.handle(" crates/roxy-http/src/accept.rs` → no matches (renamed to `handle_tunneled`).
- `grep -rn "ConnHandler" crates/roxy-http/src/accept.rs` → trait has `handle_tunneled` and `handle_plain` methods.
- `cargo build --release --workspace` → clean.
- `cargo test --workspace` → all tests pass, including new `plain_http_request_is_proxied_and_cached` and four new handler unit tests.
- `bd show roxy-o69` → status `closed`.
- Manual smoke (optional): `cargo run -- serve --listen 127.0.0.1:8888` in one shell; `curl -x http://127.0.0.1:8888 http://httpbin.org/get` (or any plain-HTTP origin) in another. First request reaches origin; second request shows a cache hit in roxy's logs.
