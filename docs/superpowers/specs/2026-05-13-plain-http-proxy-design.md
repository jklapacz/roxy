# Plain HTTP Proxy Support

**Issue:** roxy-o69
**Date:** 2026-05-13
**Status:** Design approved, awaiting plan

## Problem

Roxy currently only handles HTTPS via CONNECT/MITM. The accept loop
(`crates/roxy-http/src/accept.rs:36-46`) drops non-CONNECT first requests
with `"non-CONNECT first request dropped"`. The README advertises a generic
"HTTP proxy interface", but real-world proxy traffic includes plain HTTP
sent in absolute-form: `GET http://example.com/ HTTP/1.1` direct to the
proxy port, no CONNECT, no TLS termination. That path is unimplemented
today, so HTTP clients configured with `HTTP_PROXY=http://roxy:8080` drop
on their first request.

## Goals

1. Roxy accepts plain HTTP requests on the same listener port as the
   existing CONNECT/HTTPS path. No new socket, no new config.
2. Plain HTTP requests are forwarded upstream and cached, reusing the
   existing `Handler` / `UpstreamRouter` / `Cache` pipeline.
3. The CONNECT/HTTPS path is unchanged in behavior and performance.

## Non-goals

- **Hop-by-hop header scrubbing** (`Connection`, `Proxy-Connection`,
  `Keep-Alive`, `TE`, `Trailers`). The existing CONNECT path has the same
  gap; cleanest as a separate follow-up across both paths.
- **`Via` header insertion** (RFC 7230). Same reasoning.
- **HTTP/2 over plaintext (h2c)** upstream support. Rare in practice.
- **Fingerprinting plain HTTP.** TLS ClientHello fingerprint is
  inapplicable without TLS; h2c fingerprint value is near zero. Plain HTTP
  requests strict-ignore `X-Roxy-Fingerprint`.

## Design

### Dispatch — peek then branch

User decision: peek the first 8 bytes of the TCP stream via
`tokio::TcpStream::peek` (`MSG_PEEK`), branch on whether they match
`b"CONNECT "`. MSG_PEEK leaves the stream untouched, so no
buffer-prepending gymnastics.

In `crates/roxy-http/src/accept.rs`, replace the per-connection
`read_connect` call with:

```rust
let mut peek_buf = [0u8; 8];
let n = match sock.peek(&mut peek_buf).await {
    Ok(n) => n,
    Err(e) => { warn!(?peer, error = %e, "peek failed"); return; }
};
if n >= 8 && &peek_buf == b"CONNECT " {
    // existing CONNECT flow: read_connect, write_200, TLS-terminate, serve_tls
} else {
    // new plain-HTTP flow
    handler.handle_plain(sock).await;
}
```

The `ConnHandler` trait gains a `handle_plain(&self, stream: TcpStream)`
method. The existing `handle(&self, authority, tls_stream)` is renamed to
`handle_tunneled` for clarity. Both `ProxyConnHandler` (`roxy-proxy/src/serve.rs`)
methods delegate to `Handler` methods of the same names.

### `serve_http_plain` helper

Mirror of `serve_tls` for plain TCP. Add to `crates/roxy-http/src/server.rs`:

```rust
pub async fn serve_http_plain<F, Fut>(stream: TcpStream, handler: F)
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<Response<BoxBody>, Infallible>> + Send + 'static,
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

Re-export from `lib.rs` alongside `serve_tls`.

### Handler refactor

`Handler::handle(authority, req)` currently assumes authority comes from
CONNECT and hardcodes `"https"` for the cache-key scheme
(`build_cache_key_and_warn` → `CacheKey::from_parts(label, method, "https", host, …)`).
Refactor:

- Extract a private `handle_inner(authority: String, scheme: &str, mut req)`
  containing the existing body.
- Rename public `handle` to `handle_tunneled`; it calls
  `handle_inner(authority, "https", req)`.
- Add a public `handle_plain(mut req)` that:
  - Extracts authority from `req.uri().authority()`. If absent, return 400
    with message `"roxy: HTTP request missing absolute-form URI"`.
  - Extracts scheme from `req.uri().scheme_str()` (expected `"http"`,
    fall back to `"http"`).
  - Silently removes any `X-Roxy-Fingerprint` header (the header is
    documented as a no-op for plain HTTP).
  - Forces the label to `DEFAULT_LABEL` so the router picks the rustls path
    unconditionally.
  - Calls `handle_inner(authority, &scheme, req)`.

`build_cache_key_and_warn` gains a `scheme: &str` parameter. The four
existing `key_tests` are updated to pass `"https"` explicitly. The URI
rebuild at `handler.rs:65` already reads `req.uri().scheme_str().unwrap_or("https")`,
which works as-is: for plain HTTP, the URI carries `http://`; for tunneled
requests, the inner request-target has no scheme and the fallback is right.

### Tests

**Handler unit tests** (extend `key_tests` in `crates/roxy-proxy/src/handler.rs`):

- `cache_key_uses_http_scheme_for_plain`: build a key with scheme `"http"`,
  verify it differs from the same logical request keyed under `"https"`.
- `handle_plain_missing_authority_returns_400`: a request with a path-only
  URI returns `400 Bad Request` with the documented message.
- `handle_plain_ignores_fingerprint_header`: a request with
  `X-Roxy-Fingerprint: chrome-137` and an absolute-form `http://` URI does
  not error and is keyed under `DEFAULT_LABEL` (the `_default` profile
  label), not `chrome-137`.

**Dispatch unit test** in `crates/roxy-http/src/accept.rs`:

- Synthesize a TCP loopback pair. Write `"CONNECT host:443 HTTP/1.1\r\n…"`
  vs `"GET http://example.com/ HTTP/1.1\r\n…"`. Verify the dispatch lands
  on the correct branch (use a fake `ConnHandler` that records which method
  was called).

**Integration test** at `crates/roxy-proxy/tests/http_plain.rs`:

- Spawn a fake plain-HTTP origin via `axum` (no TLS — distinct from the
  existing `axum-server` fixture which uses rustls).
- Spawn roxy with the test fixture config.
- Send `GET http://<origin>/ …` through roxy using `reqwest` configured
  with `.proxy(reqwest::Proxy::http(roxy_addr))`.
- Verify response body and status.
- Send the same request again; verify origin's hit counter does not
  increment (cache hit).

## Risk / migration notes

- **`TcpStream::peek` semantics.** Uses `MSG_PEEK` underneath, well-supported
  on macOS and Linux. No known edge cases for our use.
- **`auto::Builder` HTTP/2 upgrade.** `serve_http_plain` reuses
  `hyper_util::server::conn::auto::Builder`, which can negotiate HTTP/2
  via ALPN. Without TLS there's no ALPN — `auto` will speak HTTP/1.1 only.
  Acceptable; h2c is out of scope. If `auto` misbehaves without TLS we can
  switch to `hyper::server::conn::http1::Builder` explicitly.
- **Behavior diff on `X-Roxy-Fingerprint` over HTTP.** Today the header is
  silently dropped by the not-CONNECT-rejected listener (never reaches the
  proxy). Post-change, the header is silently dropped inside `handle_plain`.
  Same observable behavior; just the dropping happens deeper in the stack.

## Out of this design

- Hop-by-hop header scrubbing (own follow-up across both CONNECT and plain
  paths).
- `Via` header insertion.
- HTTP/2 over plaintext (h2c) upstream support.
- Fingerprinting plain HTTP requests.
