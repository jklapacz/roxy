# Upstream Proxy Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route roxy's outbound connections through a single statically-configured HTTP CONNECT proxy, for both the rustls `UpstreamClient` path and the wreq `ImpersonateClient` path.

**Architecture:** A new `[upstream]` config section yields an optional typed `ProxyEndpoint`. The rustls path gets a hand-rolled `ProxyConnector` (`tower::Service<Uri>`) that CONNECT-tunnels through the proxy *below* the existing TLS layer. The wreq path uses wreq's native `Proxy`. The `ProxyEndpoint` type is the unit a future rotating pool would hold many of — v1 builds no rotation machinery.

**Tech Stack:** Rust, hyper-util `HttpConnector` + `tower-service`, hyper-rustls, wreq, `url` crate (proxy URL parsing), `base64` (Proxy-Authorization).

**Spec:** `docs/superpowers/specs/2026-05-14-upstream-proxy-support-design.md` (beads issue roxy-q6r).

**Spec deviations (intentional, flagged for review):**

1. **No `UpstreamError::ProxyConnect` variant.** The connector error is opaque inside hyper-util's `legacy::Error`, so a typed variant would need fragile error-chain sniffing. Proxy failures surface as the existing `UpstreamError::Client` → **502**, with the connector's message in the error source chain. The spec's error-handling section has been updated to match.

2. **No `ProxyPool` type.** The spec sketched a `ProxyPool { endpoints: Vec<ProxyEndpoint> }` holder with `.select()` as the rotation seam. This plan uses `Option<ProxyEndpoint>` directly — for a v1 with exactly one proxy, a `Vec`-backed pool with a vacuous `select()` is rotation machinery the spec's own non-goals say to defer (YAGNI). Adding rotation later means introducing `ProxyPool` then and changing the two `with_proxy` signatures — a contained, additive change. If you want the `ProxyPool` seam in v1, say so and I'll revise.

---

## File Structure

**Created:**
- `crates/roxy-config/src/proxy.rs` — `ProxyEndpoint`, `ProxyAuth`, `parse_proxy`. One responsibility: proxy URL → typed endpoint.
- `crates/roxy-http/src/proxy_connector.rs` — `ProxyConnector` (the `tower::Service`), the CONNECT handshake, and the status-line parser.
- `crates/roxy-proxy/tests/common/fake_proxy.rs` — in-process fake CONNECT proxy for integration tests.
- `crates/roxy-proxy/tests/upstream_proxy.rs` — end-to-end integration tests.

**Modified:**
- `crates/roxy-config/src/lib.rs` — add `UpstreamConfig`, wire `upstream` into `Config`, validate in `with_expanded_paths`, re-export proxy types.
- `crates/roxy-config/src/error.rs` — add `ConfigError::Proxy`.
- `crates/roxy-config/Cargo.toml` — add `url`.
- `crates/roxy-http/src/lib.rs` — declare `mod proxy_connector`.
- `crates/roxy-http/src/upstream.rs` — `UpstreamClient::with_proxy`, connector type change.
- `crates/roxy-http/Cargo.toml` — add `roxy-config`, `base64`, `tower-service`.
- `crates/roxy-impersonate/src/client.rs` — `proxy` field, `with_proxy`, wreq proxy plumbing.
- `crates/roxy-impersonate/Cargo.toml` — add `roxy-config`.
- `crates/roxy-proxy/src/serve.rs` — parse proxy from config, pass into both clients.
- `crates/roxy-proxy/tests/common/mod.rs` — `FixtureBuilder::upstream_proxy`, declare `fake_proxy` module.
- `README.md` — document `[upstream]`.

---

## Task 1: roxy-config — `ProxyEndpoint`, `ProxyAuth`, `parse_proxy`

**Files:**
- Create: `crates/roxy-config/src/proxy.rs`
- Modify: `crates/roxy-config/src/error.rs`
- Modify: `crates/roxy-config/src/lib.rs:3-4` (module decl + re-export)
- Modify: `crates/roxy-config/Cargo.toml`

- [ ] **Step 1: Add the `url` dependency**

`url = "2.5"` is already in the root `[workspace.dependencies]`. In `crates/roxy-config/Cargo.toml`, under `[dependencies]`, after `dirs = { workspace = true }`, add:

```toml
url = { workspace = true }
```

- [ ] **Step 2: Add the `ConfigError::Proxy` variant**

In `crates/roxy-config/src/error.rs`, add a variant inside `enum ConfigError` after `Expand`:

```rust
    #[error("upstream proxy config: {0}")]
    Proxy(String),
```

- [ ] **Step 3: Write the failing tests for `parse_proxy`**

Create `crates/roxy-config/src/proxy.rs` with the test module first (the rest of the file is added in Step 5; this will not compile yet):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_and_port() {
        let ep = parse_proxy("http://corp-proxy:8080").unwrap();
        assert_eq!(ep.host, "corp-proxy");
        assert_eq!(ep.port, 8080);
        assert_eq!(ep.auth, None);
    }

    #[test]
    fn parses_userinfo_into_auth() {
        let ep = parse_proxy("http://alice:s3cret@corp-proxy:8080").unwrap();
        assert_eq!(ep.host, "corp-proxy");
        assert_eq!(ep.port, 8080);
        assert_eq!(
            ep.auth,
            Some(ProxyAuth {
                username: "alice".to_string(),
                password: "s3cret".to_string(),
            })
        );
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err = parse_proxy("socks5://corp-proxy:1080").unwrap_err();
        assert!(matches!(err, ConfigError::Proxy(_)), "got: {err:?}");
    }

    #[test]
    fn rejects_missing_port() {
        let err = parse_proxy("http://corp-proxy").unwrap_err();
        assert!(matches!(err, ConfigError::Proxy(_)), "got: {err:?}");
    }

    #[test]
    fn rejects_garbage() {
        let err = parse_proxy("not a url").unwrap_err();
        assert!(matches!(err, ConfigError::Proxy(_)), "got: {err:?}");
    }

    #[test]
    fn url_no_auth_omits_credentials() {
        let ep = parse_proxy("http://alice:s3cret@corp-proxy:8080").unwrap();
        assert_eq!(ep.url_no_auth(), "http://corp-proxy:8080");
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p roxy-config --lib proxy`
Expected: FAIL — compile error (`parse_proxy`, `ProxyEndpoint`, `ProxyAuth` not defined).

- [ ] **Step 5: Implement the proxy types and parser**

Prepend to `crates/roxy-config/src/proxy.rs` (above the `#[cfg(test)]` module):

```rust
//! Upstream proxy endpoint types and parsing. v1 supports a single HTTP
//! CONNECT proxy; `ProxyEndpoint` is the unit a future rotating pool would
//! hold many of.

use crate::ConfigError;

/// Basic-auth credentials for an upstream proxy, parsed from the userinfo
/// component of the proxy URL (`http://user:pass@host:port`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// A single resolved upstream proxy. v1 config yields zero or one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
}

impl ProxyEndpoint {
    /// Scheme-qualified URL WITHOUT userinfo. Credentials are carried
    /// separately (see `auth`) so they never end up in a logged URL string.
    pub fn url_no_auth(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

/// Parse a proxy URL of the form `http://[user:pass@]host:port`.
///
/// v1 accepts only the `http` scheme and requires an explicit port. A missing
/// host, missing port, non-`http` scheme, or unparseable URL is a
/// `ConfigError::Proxy` so misconfiguration fails fast at startup.
pub fn parse_proxy(raw: &str) -> Result<ProxyEndpoint, ConfigError> {
    let u = url::Url::parse(raw)
        .map_err(|e| ConfigError::Proxy(format!("invalid proxy URL {raw:?}: {e}")))?;
    if u.scheme() != "http" {
        return Err(ConfigError::Proxy(format!(
            "proxy scheme must be \"http\", got {:?} in {raw:?}",
            u.scheme()
        )));
    }
    let host = u
        .host_str()
        .ok_or_else(|| ConfigError::Proxy(format!("proxy URL {raw:?} has no host")))?
        .to_string();
    let port = u
        .port()
        .ok_or_else(|| ConfigError::Proxy(format!("proxy URL {raw:?} has no explicit port")))?;
    let auth = if u.username().is_empty() {
        None
    } else {
        Some(ProxyAuth {
            username: u.username().to_string(),
            password: u.password().unwrap_or("").to_string(),
        })
    };
    Ok(ProxyEndpoint { host, port, auth })
}
```

- [ ] **Step 6: Wire the module into the crate**

In `crates/roxy-config/src/lib.rs`, after the existing `mod error;` / `pub use error::ConfigError;` lines (around line 3-4), add:

```rust
mod proxy;
pub use proxy::{parse_proxy, ProxyAuth, ProxyEndpoint};
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p roxy-config --lib proxy`
Expected: PASS — all 6 tests green.

- [ ] **Step 8: Commit**

```bash
git add crates/roxy-config/src/proxy.rs crates/roxy-config/src/error.rs crates/roxy-config/src/lib.rs crates/roxy-config/Cargo.toml Cargo.lock
git commit -m "feat(roxy-config): ProxyEndpoint type and proxy URL parser"
```

---

## Task 2: roxy-config — `UpstreamConfig` wired into `Config`

**Files:**
- Modify: `crates/roxy-config/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

In `crates/roxy-config/src/lib.rs`, inside `mod tests`, add these tests at the end of the module (before the closing `}`):

```rust
    #[test]
    fn upstream_section_defaults_to_no_proxy() {
        let c = Config::default();
        assert_eq!(c.upstream.proxy, None);
        assert_eq!(c.upstream.endpoint().unwrap(), None);
    }

    #[test]
    fn upstream_proxy_parses_from_toml() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"[upstream]"#).unwrap();
        writeln!(f, r#"proxy = "http://corp-proxy:8080""#).unwrap();
        let c = load_from_path(f.path()).unwrap();
        let ep = c.upstream.endpoint().unwrap().unwrap();
        assert_eq!(ep.host, "corp-proxy");
        assert_eq!(ep.port, 8080);
    }

    #[test]
    fn malformed_upstream_proxy_fails_at_load() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"[upstream]"#).unwrap();
        writeln!(f, r#"proxy = "socks5://corp-proxy:1080""#).unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Proxy(_)), "got: {err:?}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p roxy-config --lib upstream`
Expected: FAIL — compile error (`Config` has no field `upstream`).

- [ ] **Step 3: Add the `UpstreamConfig` struct**

In `crates/roxy-config/src/lib.rs`, after the `CaptureConfig` struct + its `Default` impl (around line 91), add:

```rust
/// Upstream proxy configuration. v1 supports a single HTTP CONNECT proxy;
/// absent => roxy dials origins directly. The `proxy` string is the serde
/// representation — call [`UpstreamConfig::endpoint`] for the parsed form.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(default)]
pub struct UpstreamConfig {
    /// Optional `http://[user:pass@]host:port` upstream proxy.
    pub proxy: Option<String>,
}

impl UpstreamConfig {
    /// Parse the configured `proxy` string into a typed endpoint. `Ok(None)`
    /// when no proxy is configured.
    pub fn endpoint(&self) -> Result<Option<ProxyEndpoint>, ConfigError> {
        self.proxy.as_deref().map(parse_proxy).transpose()
    }
}
```

- [ ] **Step 4: Add the `upstream` field to `Config`**

In `crates/roxy-config/src/lib.rs`, in the `struct Config` definition (around line 12-19), add a field after `capture: CaptureConfig,`:

```rust
    pub upstream: UpstreamConfig,
```

In `impl Default for Config` (around line 93-104), add to the struct literal after `capture: CaptureConfig::default(),`:

```rust
            upstream: UpstreamConfig::default(),
```

- [ ] **Step 5: Validate the proxy at load time**

In `crates/roxy-config/src/lib.rs`, in `impl Config { pub fn with_expanded_paths(...) }` (around line 151-158), add this line just before `Ok(self)`:

```rust
        // Validate the proxy URL at load time so misconfiguration fails fast
        // at startup rather than at the first request. The parsed value is
        // discarded here; callers re-parse via `UpstreamConfig::endpoint`.
        self.upstream.endpoint()?;
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p roxy-config`
Expected: PASS — all roxy-config tests green, including the 3 new ones.

- [ ] **Step 7: Commit**

```bash
git add crates/roxy-config/src/lib.rs
git commit -m "feat(roxy-config): [upstream] proxy config section"
```

---

## Task 3: roxy-http — deps and the CONNECT status-line parser

**Files:**
- Modify: `crates/roxy-http/Cargo.toml`
- Create: `crates/roxy-http/src/proxy_connector.rs`
- Modify: `crates/roxy-http/src/lib.rs:3-7` (module decl)

- [ ] **Step 1: Add dependencies**

In `crates/roxy-http/Cargo.toml`, under `[dependencies]`, add (after `pin-project-lite = { workspace = true }`):

```toml
roxy-config = { workspace = true }
base64 = "0.22"
tower-service = "0.3"
```

- [ ] **Step 2: Declare the module**

In `crates/roxy-http/src/lib.rs`, in the block of `pub mod` declarations (lines 3-7), add (a private module — `ProxyConnector` is an implementation detail of `UpstreamClient`):

```rust
mod proxy_connector;
```

- [ ] **Step 3: Write the failing tests for `parse_status_line`**

Create `crates/roxy-http/src/proxy_connector.rs` with only the test module for now (the rest of the file lands in Task 4 / Task 5; this will not compile yet):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_200() {
        let raw = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        assert_eq!(parse_status_line(raw).unwrap(), 200);
    }

    #[test]
    fn parses_407() {
        let raw = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
        assert_eq!(parse_status_line(raw).unwrap(), 407);
    }

    #[test]
    fn rejects_non_http_first_line() {
        assert!(parse_status_line(b"garbage here\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_missing_code() {
        assert!(parse_status_line(b"HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_non_numeric_code() {
        assert!(parse_status_line(b"HTTP/1.1 twohundred OK\r\n\r\n").is_err());
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p roxy-http --lib proxy_connector`
Expected: FAIL — compile error (`parse_status_line` not defined).

- [ ] **Step 5: Implement `parse_status_line` and the file header**

Prepend to `crates/roxy-http/src/proxy_connector.rs` (above the `#[cfg(test)]` module):

```rust
//! `ProxyConnector` — a `tower::Service<Uri>` that optionally CONNECT-tunnels
//! through an upstream HTTP proxy before the TLS layer runs. When no proxy is
//! configured it delegates straight to `HttpConnector`, byte-identical to the
//! direct path.

use base64::Engine as _;
use http::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use roxy_config::{ProxyAuth, ProxyEndpoint};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tower_service::Service;

/// Boxed connector error — unifies `HttpConnector`'s error with our own
/// `io::Error`s from the CONNECT handshake.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Maximum bytes buffered while reading a proxy's CONNECT response header
/// block. A well-behaved proxy's response is tiny; the cap stops a
/// misbehaving proxy from making us buffer without bound.
const MAX_CONNECT_RESPONSE: usize = 8 * 1024;

/// Parse the status code out of an HTTP/1.x response header block. Expects a
/// first line shaped like `HTTP/1.1 200 Connection Established`.
fn parse_status_line(raw: &[u8]) -> Result<u16, BoxError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| -> BoxError { "proxy CONNECT response is not valid UTF-8".into() })?;
    let first = text
        .lines()
        .next()
        .ok_or_else(|| -> BoxError { "empty proxy CONNECT response".into() })?;
    let mut parts = first.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(format!("malformed proxy CONNECT status line: {first:?}").into());
    }
    let code = parts
        .next()
        .ok_or_else(|| -> BoxError { format!("missing status code in: {first:?}").into() })?;
    code.parse::<u16>()
        .map_err(|_| format!("non-numeric status code in: {first:?}").into())
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p roxy-http --lib proxy_connector`
Expected: PASS — 5 tests green. (Unused-import warnings for the not-yet-used imports are expected and resolved in Task 4.)

- [ ] **Step 7: Commit**

```bash
git add crates/roxy-http/Cargo.toml crates/roxy-http/src/lib.rs crates/roxy-http/src/proxy_connector.rs Cargo.lock
git commit -m "feat(roxy-http): CONNECT status-line parser, proxy_connector deps"
```

---

## Task 4: roxy-http — the CONNECT handshake (`connect_tunnel`, `read_connect_response`)

**Files:**
- Modify: `crates/roxy-http/src/proxy_connector.rs`

- [ ] **Step 1: Write the failing tests**

In `crates/roxy-http/src/proxy_connector.rs`, add a scriptable fake-proxy test helper plus tests inside the existing `#[cfg(test)] mod tests` (add after the `parse_status_line` tests, before the module's closing `}`). `Arc`, `AsyncReadExt`, `AsyncWriteExt`, `TcpStream` are already in scope via the test module's `use super::*;`; only `Mutex` needs an explicit import:

```rust
    use std::sync::Mutex;

    /// Spawn a one-shot fake proxy: accept a connection, read the request
    /// header block (up to `\r\n\r\n`) into the returned buffer, write
    /// `response`, then close. Returns the listen addr and the captured
    /// request bytes (filled once a client connects).
    async fn fake_proxy_endpoint(
        response: &'static [u8],
    ) -> (std::net::SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_c = captured.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = sock.read(&mut byte).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            *captured_c.lock().unwrap() = buf;
            let _ = sock.write_all(response).await;
        });
        (addr, captured)
    }

    #[tokio::test]
    async fn connect_tunnel_succeeds_on_200() {
        let (addr, captured) =
            fake_proxy_endpoint(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        connect_tunnel(&mut tcp, "example.com", 443, None)
            .await
            .unwrap();
        let req = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
            "got: {req:?}"
        );
        assert!(!req.contains("Proxy-Authorization"), "got: {req:?}");
    }

    #[tokio::test]
    async fn connect_tunnel_sends_basic_auth() {
        let (addr, captured) =
            fake_proxy_endpoint(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let auth = ProxyAuth {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        connect_tunnel(&mut tcp, "example.com", 443, Some(&auth))
            .await
            .unwrap();
        let req = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        // base64("user:pass") == "dXNlcjpwYXNz"
        assert!(
            req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
            "got: {req:?}"
        );
    }

    #[tokio::test]
    async fn connect_tunnel_errors_on_407() {
        let (addr, _captured) =
            fake_proxy_endpoint(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let err = connect_tunnel(&mut tcp, "example.com", 443, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("407"), "got: {err}");
    }

    #[tokio::test]
    async fn connect_tunnel_errors_when_proxy_closes() {
        let (addr, _captured) = fake_proxy_endpoint(b"").await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let err = connect_tunnel(&mut tcp, "example.com", 443, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("closed"), "got: {err}");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p roxy-http --lib proxy_connector`
Expected: FAIL — compile error (`connect_tunnel` not defined).

- [ ] **Step 3: Implement `connect_tunnel` and `read_connect_response`**

In `crates/roxy-http/src/proxy_connector.rs`, add after the `parse_status_line` function (above the `#[cfg(test)]` module):

```rust
/// Perform the HTTP CONNECT handshake on an already-open TCP stream to the
/// proxy. On success the stream is an opaque tunnel to `host:port`.
async fn connect_tunnel(
    tcp: &mut TcpStream,
    host: &str,
    port: u16,
    auth: Option<&ProxyAuth>,
) -> Result<(), BoxError> {
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(a) = auth {
        let creds = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", a.username, a.password));
        req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes()).await?;

    let raw = read_connect_response(tcp).await?;
    let status = parse_status_line(&raw)?;
    if status != 200 {
        return Err(format!("upstream proxy refused CONNECT: status {status}").into());
    }
    Ok(())
}

/// Read a proxy's CONNECT response header block (status line + headers up to
/// the terminating `\r\n\r\n`). Reads one byte at a time so we never consume
/// past the header terminator into the tunnel body — the proxy sends nothing
/// after the response until we send tunnel data, so this cannot under-read.
async fn read_connect_response(tcp: &mut TcpStream) -> Result<Vec<u8>, BoxError> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = tcp.read(&mut byte).await?;
        if n == 0 {
            return Err("upstream proxy closed connection during CONNECT".into());
        }
        buf.push(byte[0]);
        if buf.len() > MAX_CONNECT_RESPONSE {
            return Err("upstream proxy CONNECT response header block too large".into());
        }
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p roxy-http --lib proxy_connector`
Expected: PASS — all 9 proxy_connector tests green.

- [ ] **Step 5: Commit**

```bash
git add crates/roxy-http/src/proxy_connector.rs
git commit -m "feat(roxy-http): HTTP CONNECT handshake for upstream proxy"
```

---

## Task 5: roxy-http — `ProxyConnector` service + `UpstreamClient::with_proxy`

**Files:**
- Modify: `crates/roxy-http/src/proxy_connector.rs`
- Modify: `crates/roxy-http/src/upstream.rs`

- [ ] **Step 1: Implement the `ProxyConnector` service**

In `crates/roxy-http/src/proxy_connector.rs`, add after `read_connect_response` (above the `#[cfg(test)]` module):

```rust
/// A `tower::Service<Uri>` connector. With `proxy = None` it delegates
/// straight to `HttpConnector` (the direct path, unchanged). With a proxy
/// set, it dials the proxy, performs the CONNECT handshake to the real
/// origin, and returns the resulting tunnel for the TLS layer above to wrap.
#[derive(Clone)]
pub struct ProxyConnector {
    inner: HttpConnector,
    proxy: Option<Arc<ProxyEndpoint>>,
}

impl ProxyConnector {
    pub fn new(inner: HttpConnector, proxy: Option<ProxyEndpoint>) -> Self {
        Self {
            inner,
            proxy: proxy.map(Arc::new),
        }
    }
}

impl Service<Uri> for ProxyConnector {
    type Response = TokioIo<TcpStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // `HttpConnector` is always ready; nothing to back-pressure.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let proxy = self.proxy.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let Some(ep) = proxy else {
                // Direct path — behavior identical to a bare HttpConnector.
                return inner.call(dst).await.map_err(|e| Box::new(e) as BoxError);
            };

            // Resolve the real origin host:port from the request URI before
            // we point the dialer at the proxy address instead.
            let host = dst
                .host()
                .ok_or_else(|| -> BoxError { "upstream uri has no host".into() })?
                .to_string();
            let port = dst.port_u16().unwrap_or_else(|| {
                if dst.scheme_str() == Some("http") {
                    80
                } else {
                    443
                }
            });

            // Dial the proxy itself via HttpConnector (keeps DNS resolution
            // and the configured TCP_NODELAY).
            let proxy_uri: Uri = format!("http://{}:{}", ep.host, ep.port)
                .parse()
                .map_err(|e| -> BoxError { format!("bad proxy uri: {e}").into() })?;
            let io = inner
                .call(proxy_uri)
                .await
                .map_err(|e| Box::new(e) as BoxError)?;
            let mut tcp = io.into_inner();

            connect_tunnel(&mut tcp, &host, port, ep.auth.as_ref()).await?;
            Ok(TokioIo::new(tcp))
        })
    }
}
```

- [ ] **Step 2: Run a build check**

Run: `cargo build -p roxy-http`
Expected: SUCCESS (no errors; the `proxy_connector` module fully compiles now).

- [ ] **Step 3: Write the failing test for `UpstreamClient::with_proxy`**

In `crates/roxy-http/src/proxy_connector.rs`, inside `#[cfg(test)] mod tests`, add this test (the helper `fake_proxy_endpoint` from Task 4 is reused):

```rust
    #[tokio::test]
    async fn upstream_client_routes_request_through_proxy() {
        use crate::UpstreamClient;
        use http_body_util::Empty;

        // Proxy replies 200 then closes — enough to prove the request reached
        // the CONNECT stage. The subsequent TLS handshake over the dead
        // tunnel fails, so the request errors; the assertion is that the
        // proxy was contacted with the right CONNECT target.
        let (addr, captured) =
            fake_proxy_endpoint(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        let ep = ProxyEndpoint {
            host: addr.ip().to_string(),
            port: addr.port(),
            auth: None,
        };
        let client = UpstreamClient::with_proxy(Some(ep)).unwrap();
        let req = http::Request::get("https://example.invalid/")
            .body(Empty::<bytes::Bytes>::new())
            .unwrap();
        // Expected to error (no real tunnel), but the proxy must have been hit.
        let _ = client.send_empty(req).await;

        let captured = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            captured.starts_with("CONNECT example.invalid:443 HTTP/1.1\r\n"),
            "proxy did not receive expected CONNECT; got: {captured:?}"
        );
    }
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test -p roxy-http --lib proxy_connector::tests::upstream_client_routes_request_through_proxy`
Expected: FAIL — compile error (`UpstreamClient::with_proxy` not defined).

- [ ] **Step 5: Add `with_proxy` to `UpstreamClient`**

In `crates/roxy-http/src/upstream.rs`:

(a) Add an import near the top (after the existing `use` block, around line 13):

```rust
use crate::proxy_connector::ProxyConnector;
```

(b) Change the `inner` field type in `struct UpstreamClient` (line 89) from:

```rust
    inner: Client<hyper_rustls::HttpsConnector<HttpConnector>, ClientBody>,
```

to:

```rust
    inner: Client<hyper_rustls::HttpsConnector<ProxyConnector>, ClientBody>,
```

(c) Replace the existing `pub fn new()` (lines 93-115) with `new` delegating to a new `with_proxy`:

```rust
    pub fn new() -> Result<Self, UpstreamError> {
        Self::with_proxy(None)
    }

    /// Construct an upstream client that routes outbound connections through
    /// `proxy`, or directly when `proxy` is `None`. The CONNECT tunnel (when
    /// a proxy is set) is established below the TLS layer, so TLS-to-origin
    /// behavior is identical either way.
    pub fn with_proxy(
        proxy: Option<roxy_config::ProxyEndpoint>,
    ) -> Result<Self, UpstreamError> {
        // Ensure a process-global rustls CryptoProvider is installed. When
        // multiple backends are present in the dep graph rustls cannot
        // auto-select; install `ring` explicitly. Ignore the result: if
        // another component already installed a provider that is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.enforce_http(false);
        let connector = ProxyConnector::new(http, proxy);
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| UpstreamError::Uri(e.to_string()))?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector);
        let inner = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(32)
            .build::<_, ClientBody>(https);
        Ok(Self { inner })
    }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p roxy-http`
Expected: PASS — the new test plus all existing roxy-http tests (`router.rs` and `upstream_h1.rs` call `UpstreamClient::new()`, whose signature is unchanged).

- [ ] **Step 7: Commit**

```bash
git add crates/roxy-http/src/proxy_connector.rs crates/roxy-http/src/upstream.rs
git commit -m "feat(roxy-http): ProxyConnector and UpstreamClient::with_proxy"
```

---

## Task 6: roxy-impersonate — wreq proxy plumbing

**Files:**
- Modify: `crates/roxy-impersonate/Cargo.toml`
- Modify: `crates/roxy-impersonate/src/client.rs`

- [ ] **Step 1: Add the `roxy-config` dependency**

In `crates/roxy-impersonate/Cargo.toml`, under `[dependencies]`, add (after `tracing = { workspace = true }`):

```toml
roxy-config = { workspace = true }
```

- [ ] **Step 2: Write the failing test**

In `crates/roxy-impersonate/src/client.rs`, inside `#[cfg(test)] mod tests`, add at the end of the module (before its closing `}`):

```rust
    #[test]
    fn with_proxy_sets_the_field() {
        let ep = roxy_config::ProxyEndpoint {
            host: "corp-proxy".to_string(),
            port: 8080,
            auth: None,
        };
        let c = ImpersonateClient::new().with_proxy(Some(ep.clone()));
        assert_eq!(c.proxy, Some(ep));
    }

    #[test]
    fn no_proxy_by_default() {
        let c = ImpersonateClient::new();
        assert_eq!(c.proxy, None);
    }
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p roxy-impersonate --lib client`
Expected: FAIL — compile error (`ImpersonateClient` has no field `proxy`, no method `with_proxy`).

- [ ] **Step 4: Add the `proxy` field**

In `crates/roxy-impersonate/src/client.rs`, in `struct ImpersonateClient` (around line 19-35), add a field after `cert_store: Option<wreq::tls::CertStore>,`:

```rust
    /// Optional upstream proxy applied to every lazily-built `wreq::Client`.
    /// `None` => wreq dials origins directly.
    proxy: Option<roxy_config::ProxyEndpoint>,
```

- [ ] **Step 5: Initialize `proxy` in `build`**

In `crates/roxy-impersonate/src/client.rs`, in the `fn build(...)` function, in the final `Self { ... }` struct literal (around line 117-123), add after `cert_store,`:

```rust
            proxy: None,
```

- [ ] **Step 6: Add the `with_proxy` method**

In `crates/roxy-impersonate/src/client.rs`, in `impl ImpersonateClient`, add after the `with_custom` method (around line 56):

```rust
    /// Route every lazily-built `wreq::Client` through `proxy`. `None` leaves
    /// the client dialing origins directly. Chainable on top of any
    /// constructor (`new`, `with_custom`, `with_custom_and_extra_root_pem`).
    pub fn with_proxy(mut self, proxy: Option<roxy_config::ProxyEndpoint>) -> Self {
        self.proxy = proxy;
        self
    }
```

- [ ] **Step 7: Apply the proxy when building each wreq client**

In `crates/roxy-impersonate/src/client.rs`, in `async fn client_for(...)`, after the `cert_store` block and before `let client = builder.build()?;` (around line 174-177), insert:

```rust
        if let Some(ep) = &self.proxy {
            // wreq's `Proxy` mirrors reqwest's API. Credentials are passed via
            // `basic_auth` rather than embedded in the URL so they never end
            // up in a logged proxy URL string.
            let mut p = wreq::Proxy::all(ep.url_no_auth())?;
            if let Some(a) = &ep.auth {
                p = p.basic_auth(&a.username, &a.password);
            }
            builder = builder.proxy(p);
        }
```

Note: if `wreq`'s proxy API names differ from reqwest's (`Proxy::all`, `Proxy::basic_auth`, `ClientBuilder::proxy`), check `wreq`'s docs and adjust — `wreq::Proxy::all` returns `wreq::Result<Proxy>`, so the `?` converts into `ImpersonateError::Wreq` via the existing `#[from]`.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test -p roxy-impersonate`
Expected: PASS — the 2 new tests plus all existing roxy-impersonate tests (no existing constructor signatures changed).

- [ ] **Step 9: Commit**

```bash
git add crates/roxy-impersonate/Cargo.toml crates/roxy-impersonate/src/client.rs Cargo.lock
git commit -m "feat(roxy-impersonate): route wreq clients through upstream proxy"
```

---

## Task 7: roxy-proxy — wire config proxy into both clients

**Files:**
- Modify: `crates/roxy-proxy/src/serve.rs`

- [ ] **Step 1: Resolve the proxy endpoint in `run`**

In `crates/roxy-proxy/src/serve.rs`, in `pub async fn run(...)`, after the `fingerprint_override` block (around line 33, before `let cache = ...`), add:

```rust
    // Parse the optional upstream proxy. `load_config` already validated the
    // URL at load time, so this re-parse is guaranteed to succeed; the `?` is
    // kept for the file-absent path that builds `Config::default()`.
    let upstream_proxy = cfg.upstream.endpoint()?;
```

- [ ] **Step 2: Pass the proxy into the rustls client**

In `crates/roxy-proxy/src/serve.rs`, replace this line (around line 64):

```rust
    let rustls = roxy_http::UpstreamClient::new().context("upstream client")?;
```

with:

```rust
    let rustls = roxy_http::UpstreamClient::with_proxy(upstream_proxy.clone())
        .context("upstream client")?;
```

- [ ] **Step 3: Pass the proxy into `build_impersonate`**

In `crates/roxy-proxy/src/serve.rs`, replace this line (around line 65):

```rust
    let impersonate = build_impersonate(&cfg)?;
```

with:

```rust
    let impersonate = build_impersonate(&cfg, upstream_proxy)?;
```

- [ ] **Step 4: Update the `build_impersonate` signature and body**

In `crates/roxy-proxy/src/serve.rs`, change the `build_impersonate` function signature (around line 85) from:

```rust
fn build_impersonate(cfg: &Config) -> anyhow::Result<Option<roxy_impersonate::ImpersonateClient>> {
```

to:

```rust
fn build_impersonate(
    cfg: &Config,
    proxy: Option<roxy_config::ProxyEndpoint>,
) -> anyhow::Result<Option<roxy_impersonate::ImpersonateClient>> {
```

Then, inside `build_impersonate`, apply `.with_proxy(...)` at the two construction sites:

(a) In the `#[cfg(any(test, feature = "test-utils"))]` block, change:

```rust
            let client =
                roxy_impersonate::ImpersonateClient::with_custom_and_extra_root_pem(customs, &pem)
                    .context("impersonate client with extra root PEM")?;
            return Ok(Some(verify_default_profile(client, cfg)?));
```

to:

```rust
            let client =
                roxy_impersonate::ImpersonateClient::with_custom_and_extra_root_pem(customs, &pem)
                    .context("impersonate client with extra root PEM")?
                    .with_proxy(proxy.clone());
            return Ok(Some(verify_default_profile(client, cfg)?));
```

(b) Near the end of the function, change:

```rust
    let client = roxy_impersonate::ImpersonateClient::with_custom(customs);
    Ok(Some(verify_default_profile(client, cfg)?))
```

to:

```rust
    let client = roxy_impersonate::ImpersonateClient::with_custom(customs).with_proxy(proxy);
    Ok(Some(verify_default_profile(client, cfg)?))
```

- [ ] **Step 5: Verify the workspace builds and existing tests pass**

Run: `cargo build --workspace && cargo test --workspace --lib`
Expected: SUCCESS — workspace compiles, all unit tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/roxy-proxy/src/serve.rs
git commit -m "feat(roxy-proxy): wire [upstream] proxy into both upstream clients"
```

---

## Task 8: integration test infra — fake CONNECT proxy + fixture support

**Files:**
- Create: `crates/roxy-proxy/tests/common/fake_proxy.rs`
- Modify: `crates/roxy-proxy/tests/common/mod.rs`

- [ ] **Step 1: Create the fake CONNECT proxy**

Create `crates/roxy-proxy/tests/common/fake_proxy.rs`:

```rust
//! In-process fake HTTP CONNECT proxy for integration tests. Reads the
//! `CONNECT host:port` request, records the target (and any
//! `Proxy-Authorization` header), then either tunnels to the real target or
//! rejects with a canned status.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

/// What the fake proxy does after reading a CONNECT request.
#[derive(Clone, Copy)]
pub enum ProxyBehavior {
    /// Reply `200` and splice bytes to the real CONNECT target.
    Tunnel,
    /// Reply `407 Proxy Authentication Required` and close.
    Reject407,
}

pub struct FakeProxy {
    pub addr: SocketAddr,
    /// CONNECT targets seen, in arrival order (e.g. "localhost:54321").
    pub connects: Arc<Mutex<Vec<String>>>,
    /// `Proxy-Authorization` header values seen (None when absent), per conn.
    pub auth: Arc<Mutex<Vec<Option<String>>>>,
    _handle: JoinHandle<()>,
}

impl FakeProxy {
    pub async fn spawn(behavior: ProxyBehavior) -> FakeProxy {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connects = Arc::new(Mutex::new(Vec::new()));
        let auth = Arc::new(Mutex::new(Vec::new()));
        let connects_c = connects.clone();
        let auth_c = auth.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                let connects = connects_c.clone();
                let auth = auth_c.clone();
                tokio::spawn(async move {
                    let _ = handle_conn(&mut client, behavior, connects, auth).await;
                });
            }
        });
        FakeProxy {
            addr,
            connects,
            auth,
            _handle: handle,
        }
    }

    /// Number of CONNECT requests seen for the exact `host:port` target.
    pub fn connect_count(&self, target: &str) -> usize {
        self.connects
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.as_str() == target)
            .count()
    }

    /// All `Proxy-Authorization` header values observed.
    pub fn auth_values(&self) -> Vec<Option<String>> {
        self.auth.lock().unwrap().clone()
    }
}

async fn handle_conn(
    client: &mut TcpStream,
    behavior: ProxyBehavior,
    connects: Arc<Mutex<Vec<String>>>,
    auth: Arc<Mutex<Vec<Option<String>>>>,
) -> std::io::Result<()> {
    // Read the request header block byte-at-a-time up to "\r\n\r\n".
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte).await?;
        if n == 0 {
            return Ok(());
        }
        buf.push(byte[0]);
        if buf.len() > 8192 {
            return Ok(());
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("");
    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    let auth_value = lines.find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("proxy-authorization") {
            Some(v.trim().to_string())
        } else {
            None
        }
    });
    connects.lock().unwrap().push(target.clone());
    auth.lock().unwrap().push(auth_value);

    match behavior {
        ProxyBehavior::Reject407 => {
            client
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await?;
            Ok(())
        }
        ProxyBehavior::Tunnel => {
            let mut upstream = match TcpStream::connect(&target).await {
                Ok(s) => s,
                Err(_) => {
                    client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
                    return Ok(());
                }
            };
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            tokio::io::copy_bidirectional(client, &mut upstream).await?;
            Ok(())
        }
    }
}
```

- [ ] **Step 2: Declare the module and add the `FixtureBuilder` field**

In `crates/roxy-proxy/tests/common/mod.rs`:

(a) After `pub mod trust;` (line 4), add:

```rust
pub mod fake_proxy;
```

(b) In `struct FixtureBuilder` (around line 131-137), add a field after `cache_enabled: bool,`:

```rust
    upstream_proxy: Option<String>,
```

(c) In `impl FixtureBuilder { pub fn new() }` (around line 140-148), add to the struct literal after `cache_enabled: true,`:

```rust
            upstream_proxy: None,
```

- [ ] **Step 3: Add the `upstream_proxy` builder method**

In `crates/roxy-proxy/tests/common/mod.rs`, in `impl FixtureBuilder`, add after the `cache_enabled` method (around line 160):

```rust
    /// Configure roxy's `[upstream] proxy`. The value is written verbatim into
    /// the generated roxy.toml.
    pub fn upstream_proxy(mut self, url: impl Into<String>) -> Self {
        self.upstream_proxy = Some(url.into());
        self
    }
```

- [ ] **Step 4: Write the `[upstream]` section into the generated config**

In `crates/roxy-proxy/tests/common/mod.rs`, in `spawn_fixture_with`, after the `needs_impersonate_section` block and before `std::fs::write(&cfg_path, cfg_text).unwrap();` (around line 371), add:

```rust
    if let Some(proxy) = &b.upstream_proxy {
        cfg_text.push_str(&format!("[upstream]\nproxy = \"{proxy}\"\n"));
    }
```

- [ ] **Step 5: Verify the test crate compiles**

Run: `cargo build -p roxy-proxy --tests`
Expected: SUCCESS — test harness compiles (the `fake_proxy` module and new builder method are unused so far; `common/mod.rs` already has `#![allow(dead_code)]`).

- [ ] **Step 6: Commit**

```bash
git add crates/roxy-proxy/tests/common/fake_proxy.rs crates/roxy-proxy/tests/common/mod.rs
git commit -m "test(roxy-proxy): fake CONNECT proxy and fixture upstream_proxy support"
```

---

## Task 9: integration tests — end-to-end through the proxy

**Files:**
- Create: `crates/roxy-proxy/tests/upstream_proxy.rs`

- [ ] **Step 1: Write the integration tests**

Create `crates/roxy-proxy/tests/upstream_proxy.rs`:

```rust
//! End-to-end integration tests for upstream proxy support. roxy is
//! configured with `[upstream] proxy` pointing at an in-process fake CONNECT
//! proxy; the tests assert traffic actually tunnels through it.

#![allow(clippy::unwrap_used)]

mod common;

use common::fake_proxy::{FakeProxy, ProxyBehavior};
use common::FixtureBuilder;

/// reqwest client wired through roxy, trusting roxy's MITM CA and the fake
/// origin's CA.
fn client(f: &common::Fixture) -> reqwest::Client {
    let proxy_url = format!("http://{}", f.roxy_addr);
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(
            reqwest::Certificate::from_pem(f.origin_ca.cert_pem.as_bytes()).unwrap(),
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn rustls_path_tunnels_through_proxy() {
    let proxy = FakeProxy::spawn(ProxyBehavior::Tunnel).await;
    let f = FixtureBuilder::new()
        .upstream_proxy(format!("http://{}", proxy.addr))
        .build()
        .await;
    let c = client(&f);

    let r = c.get(f.fake_origin_url("/echo/hello")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "hello");

    // The request reached the origin *via* the fake proxy.
    assert_eq!(proxy.connect_count(&f.origin_host), 1);
}

#[tokio::test]
async fn wreq_path_tunnels_through_proxy() {
    let proxy = FakeProxy::spawn(ProxyBehavior::Tunnel).await;
    let f = FixtureBuilder::new()
        .default_profile("chrome-137")
        .inject_origin_ca_into_wreq()
        .upstream_proxy(format!("http://{}", proxy.addr))
        .build()
        .await;
    let c = client(&f);

    let r = c.get(f.fake_origin_url("/echo/world")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "world");

    assert_eq!(proxy.connect_count(&f.origin_host), 1);
}

#[tokio::test]
async fn proxy_basic_auth_is_sent() {
    let proxy = FakeProxy::spawn(ProxyBehavior::Tunnel).await;
    let f = FixtureBuilder::new()
        .upstream_proxy(format!("http://user:pass@{}", proxy.addr))
        .build()
        .await;
    let c = client(&f);

    let r = c.get(f.fake_origin_url("/echo/auth")).send().await.unwrap();
    assert_eq!(r.status(), 200);

    // base64("user:pass") == "dXNlcjpwYXNz"
    let auth = proxy.auth_values();
    assert!(
        auth.iter().any(|v| v.as_deref() == Some("Basic dXNlcjpwYXNz")),
        "expected Proxy-Authorization header; saw: {auth:?}"
    );
}

#[tokio::test]
async fn proxy_rejection_surfaces_as_502() {
    let proxy = FakeProxy::spawn(ProxyBehavior::Reject407).await;
    let f = FixtureBuilder::new()
        .upstream_proxy(format!("http://{}", proxy.addr))
        .build()
        .await;
    let c = client(&f);

    // roxy's upstream client fails the CONNECT; roxy returns 502 to the client.
    let r = c.get(f.fake_origin_url("/echo/nope")).send().await.unwrap();
    assert_eq!(r.status(), 502);
}
```

- [ ] **Step 2: Run the new integration tests**

Run: `cargo test -p roxy-proxy --test upstream_proxy`
Expected: PASS — all 4 tests green.

- [ ] **Step 3: Run the full integration suite as a regression guard**

Run: `cargo test -p roxy-proxy`
Expected: PASS — all existing integration tests (`smoke`, `errors`, `impersonate`, `golden`, `http_plain`, `cache_disabled`, `ttl`, `streaming`, `fingerprint_*`) still pass unchanged. (`smoke`'s internet-requiring test stays `#[ignore]`.)

- [ ] **Step 4: Commit**

```bash
git add crates/roxy-proxy/tests/upstream_proxy.rs
git commit -m "test(roxy-proxy): end-to-end upstream proxy integration tests"
```

---

## Task 10: documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add an `## Upstream proxy` section to the README**

In `README.md`, add a new section after the `# Fingerprint emulation` section's content and before `# Upgrading` (place it as a top-level `# Upstream proxy` section, matching the README's heading style):

```markdown
# Upstream proxy

roxy can route its **outbound** connections through another HTTP proxy — a
corporate egress proxy, or a commercial proxy service. v1 supports a single,
statically-configured HTTP CONNECT proxy.

## Configuration

```toml
[upstream]
# Optional. Absent => roxy dials origins directly.
# Form: http://[user:pass@]host:port — only the http scheme is supported,
# and the port is required.
proxy = "http://user:pass@corp-proxy:8080"
```

A malformed proxy URL, a non-`http` scheme, or a missing host/port fails at
startup rather than at the first request.

The proxy applies to both upstream paths: the default rustls path and the
wreq-based fingerprint-emulation path. roxy `CONNECT`-tunnels to each origin
through the proxy, then performs its own TLS over the tunnel — so origin TLS
behavior (including fingerprint emulation) is unaffected.

Basic-auth credentials in the URL userinfo are sent as a
`Proxy-Authorization: Basic` header on the CONNECT request and are never
written to logs.
```

- [ ] **Step 2: Verify the README renders sensibly**

Run: `git diff README.md`
Expected: the new section is well-formed Markdown with a fenced `toml` block.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document [upstream] proxy configuration"
```

---

## Final verification

- [ ] **Step 1: Full workspace build + test**

Run: `cargo build --workspace && cargo test --workspace`
Expected: SUCCESS — everything compiles, all unit and integration tests pass (internet-requiring `#[ignore]` tests stay skipped).

- [ ] **Step 2: Lints**

Run: `cargo clippy --workspace --all-targets`
Expected: no warnings (the repo has `[lints] workspace = true`; `unwrap` in tests is already allowed via `#![cfg_attr(test, allow(clippy::unwrap_used))]` / `#![allow(clippy::unwrap_used)]` in test files).

- [ ] **Step 3: Close the beads issue**

```bash
bd close roxy-q6r --reason="Implemented [upstream] proxy support: single HTTP CONNECT proxy for both rustls and wreq paths"
git push
```
