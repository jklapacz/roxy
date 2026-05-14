# Upstream proxy support — design

**Date:** 2026-05-14
**Beads issue:** roxy-q6r
**Status:** approved, ready for planning

## Problem

The README advertises "Configurable upstream proxy support" but no config or
code exists. roxy always dials origins directly. Operators need roxy's outbound
connections to route through another HTTP proxy — corporate egress proxies, and
(for the scraping use case) commercial proxy services.

## Scope

**v1:** a single, statically-configured HTTP CONNECT proxy.

- HTTP CONNECT proxies only (`http://...`). No HTTPS-proxy (TLS to the proxy
  itself) and no SOCKS5 in v1.
- Config-only. No `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` env-var support in
  v1.
- Basic auth via URI userinfo (`http://user:pass@host:port`).
- Must work for **both** outbound paths: the rustls `UpstreamClient`
  (`roxy-http`) and the wreq `ImpersonateClient` (`roxy-impersonate`).

**Explicitly deferred (designed for, not built):** a rotating proxy pool. v1
introduces the type seam (`ProxyPool` holding a single endpoint) so a future
pool is a purely additive change — no machinery is built in v1.

**Non-goals:** env-var config, NO_PROXY bypass lists, HTTPS/SOCKS proxies,
per-request proxy selection.

## Architecture

### Config schema (`roxy-config`)

New `[upstream]` section:

```toml
[upstream]
proxy = "http://user:pass@corp-proxy:8080"   # optional; absent => direct
```

- New `UpstreamConfig { proxy: Option<String> }` field on `Config`, with
  `#[serde(default)]` like the other sections. The raw `String` is retained for
  round-trip serialization.
- Validation happens during post-load processing (alongside the existing path
  expansion in `Config::with_expanded_paths`): the raw `proxy` string is parsed
  into a typed `ProxyEndpoint`. A malformed URI, a non-`http` scheme, or a
  missing host/port is a `ConfigError` — roxy fails fast at startup, not at the
  first request.
- `Config` exposes the parsed result so `serve.rs` can hand it to both client
  constructors.

### Internal types

Typed endpoint (defined in `roxy-config`, consumed by `roxy-http` and
`roxy-impersonate`):

```rust
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
}
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}
```

`ProxyEndpoint` provides a helper to render its scheme-qualified URL
(`http://host:port`) **without** userinfo — credentials are passed separately
so they never land in a logged URL.

Rotation seam (v1 = single endpoint):

```rust
pub struct ProxyPool { endpoints: Vec<ProxyEndpoint> }   // v1: 0 or 1 entry

impl ProxyPool {
    pub fn select(&self) -> Option<&ProxyEndpoint> { self.endpoints.first() }
}
```

v1 builds nothing beyond this. A future rotating pool changes `select()` and
the config parse only.

### rustls path — hand-rolled CONNECT connector (`roxy-http`)

roxy MITMs, so upstream connections are almost always HTTPS; through an HTTP
proxy that means `CONNECT origin:443`, then roxy performs its own TLS over the
tunnel. Plain-HTTP origins also go through `CONNECT` (to `:80`) so the connector
logic is uniform.

New module `roxy-http/src/proxy_connector.rs`:

```rust
#[derive(Clone)]
pub struct ProxyConnector {
    inner: HttpConnector,
    proxy: Option<Arc<ProxyEndpoint>>,
}
```

It implements `tower::Service<Uri>` — the shape
`HttpsConnectorBuilder::wrap_connector` expects.

- **`proxy == None`** → delegates straight to `inner.call(uri)`. Byte-identical
  to today's direct path.
- **`proxy == Some(ep)`**:
  1. Dial the *proxy* address via `inner` (rewrite the target `Uri` to the
     proxy's host:port so `HttpConnector` connects there).
  2. Write the CONNECT request to the returned `TcpStream`:
     ```
     CONNECT origin-host:origin-port HTTP/1.1
     Host: origin-host:origin-port
     Proxy-Authorization: Basic <base64>      (only when ep.auth is set)

     ```
     The origin host:port comes from the *original* `Uri`.
  3. Read the response: status line + headers until `\r\n\r\n`. Require `200`.
     Any other status, a closed socket, or a header block exceeding an 8 KiB
     cap is a connector error.
  4. On `200`, return the same `TcpStream` — now an opaque tunnel.

**Connector stack:** `HttpsConnector<ProxyConnector>` replaces
`HttpsConnector<HttpConnector>`. The TLS-to-origin layer and its
`.with_native_roots()` config are untouched, so the integration-test private-CA
injection continues to work as-is. HTTP/2 to the origin still works — ALPN is
negotiated by the TLS layer *above* the tunnel; the proxy only sees the opaque
CONNECT tunnel.

**CONNECT response parsing** is a small dedicated function: read into a buffer
until `\r\n\r\n`, parse the first line for the status code, discard the rest.
~15 lines, unit-testable against canned byte slices, with the 8 KiB cap so a
misbehaving proxy cannot make roxy buffer unbounded.

**Constructor change:** `UpstreamClient::new()` → `UpstreamClient::new(proxy:
Option<ProxyEndpoint>)`, which builds the `ProxyConnector` with or without the
endpoint.

### wreq path (`roxy-impersonate`)

- `ImpersonateClient::with_custom` (and the `test-utils` constructor) gain a
  `proxy: Option<ProxyEndpoint>` parameter, stored on the struct alongside
  `cert_store`.
- In `client_for`, when building each lazy per-profile `wreq::Client`:
  ```rust
  if let Some(ep) = &self.proxy {
      let mut p = wreq::Proxy::all(ep.url())?;
      if let Some(a) = &ep.auth {
          p = p.basic_auth(&a.username, &a.password);
      }
      builder = builder.proxy(p);
  }
  ```
- wreq performs CONNECT tunneling natively — no connector work on this side.
  The proxy applies uniformly to every profile's client.

### Wiring (`roxy-proxy/src/serve.rs`)

`run` parses config, obtains the optional `ProxyEndpoint` from
`UpstreamConfig`, and passes it into both `UpstreamClient::new(..)` and
`build_impersonate(..)` → `ImpersonateClient`. Both feed the existing
`UpstreamRouter`.

## Error handling

- **Config-time** (malformed / non-http proxy URI) → `ConfigError`; roxy exits
  at startup with a clear message.
- **rustls path runtime** — proxy failures (proxy unreachable, CONNECT
  returned non-200, tunnel closed mid-handshake, header block over the cap)
  originate in the `ProxyConnector` and are surfaced by hyper-util's legacy
  `Client` as `UpstreamError::Client`. No dedicated `UpstreamError` variant is
  added: the connector error would be opaque inside `legacy::Error`, and
  extracting a typed variant would require fragile error-chain inspection. The
  outcome is unchanged — a **502** to the client (same as any other
  `UpstreamError::Client`), and the connector's error string (e.g. `upstream
  proxy refused CONNECT: status 407`) is carried in the error's source chain.
- **wreq path runtime** — proxy failures fold into the existing
  `ImpersonateError::Wreq` variant → also **502**. No new variant needed.
- **Credentials never logged.** Tracing on the proxy path logs `host:port`
  only, never userinfo.

## Testing

### `roxy-config` unit tests
- `[upstream] proxy = "..."` parses; absent → `None`.
- userinfo → `ProxyAuth` populated; no userinfo → `None`.
- malformed URI, non-`http` scheme, missing host/port → `ConfigError`.

### CONNECT parse unit tests (`roxy-http`, canned byte slices, no sockets)
- `HTTP/1.1 200 ...\r\n\r\n` → Ok.
- `407`, `502`, garbage first line → error with status surfaced.
- header block over the 8 KiB cap → error.

### Integration tests
Add a minimal in-process fake CONNECT proxy helper to the existing test fixture
(the one that already spins a fake origin behind a private CA). It accepts TCP,
reads the `CONNECT` line, optionally asserts `Proxy-Authorization`, replies
`200`, then splices bytes both ways to the real fake origin.

- **rustls path:** request through roxy with `[upstream] proxy` set → assert it
  arrives at the origin *via* the proxy (proxy records the CONNECT target).
- **wreq path:** same, with a fingerprint profile active → assert the
  impersonated request tunnels through the proxy.
- **auth:** proxy configured with userinfo → fake proxy asserts the
  `Proxy-Authorization: Basic` header.
- **failure:** fake proxy replies `407` (or closes) → assert roxy returns
  **502** to the client.
- **no proxy configured:** existing direct-path integration tests still pass
  unchanged (regression guard).
