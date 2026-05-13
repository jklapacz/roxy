# Harden CacheKey against silent host fallback

**Issue:** roxy-4gj
**Date:** 2026-05-13
**Status:** Design approved, awaiting plan

## Problem

`CacheKey::from_request` (`crates/roxy-cache/src/key.rs:45-65`) picks the host
for the cache key using this fallback chain:

1. `req.uri().host()` — the request URI's authority. Normally empty inside a
   tunneled HTTPS request (path-only request-target form).
2. `Host` header — **client-controlled, therefore attacker-controllable** inside
   the TLS tunnel.
3. `default_host` parameter — passed in by the caller as the CONNECT authority.

In practice, branch (2) wins on every tunneled HTTPS request, because the URI
host is empty and the Host header is present.

Meanwhile, `handler.rs:71-72` rebuilds the upstream URI using the CONNECT
authority (not the Host header). So the cache is keyed by one host while the
actual fetch goes to another.

### Concrete exploit

1. Client opens `CONNECT bank.com:443`. TLS is terminated to `bank.com`.
2. Inside the tunnel, the client sends `GET / HTTP/1.1\nHost: attacker.com`.
3. Cache key is built under host `attacker.com`.
4. Upstream request goes to `bank.com` (CONNECT authority).
5. Response from `bank.com` is written into the cache under a key naming
   `attacker.com`.
6. A later session that CONNECTs to `attacker.com` and sends `Host: attacker.com`
   hits that cache entry and receives `bank.com`'s content as if it were
   `attacker.com`'s.

The cache-poisoning vector is reachable by any client of the proxy with no
special privilege.

### Secondary inconsistency

Port handling differs across the fallback branches: `uri.host()` and the Host
header (commonly) give a bare host, while CONNECT authorities arrive as
`host:port`. Same logical resource can produce different cache keys depending
on which branch wins. This goes away once the fallback chain is removed.

## Goals

1. The cache key for any request inside a TLS tunnel derives from the CONNECT
   authority — never from URI host or Host header.
2. Operators get a structured warning when a client sends a Host header (or
   absolute-form URI host) that disagrees with the CONNECT authority. The
   request is not rejected.
3. The unsafe API (`CacheKey::from_request`) is removed so it cannot be
   reintroduced.

## Non-goals

- No change to the on-disk cache layout or wire format. Pre-existing cache
  entries become unreachable under the new keying scheme; this is desirable
  (they were keyed by attacker-controllable input). No migration required.
- No 400 rejection on Host-mismatch. Warn-and-continue was selected to avoid
  breaking edge-case clients.
- No additional authority validation (e.g. SNI vs CONNECT authority). Out of
  scope for this change.

## Design

Two crates are touched: `roxy-cache` shrinks its API; `roxy-proxy` migrates the
single callsite and adds the mismatch warning.

### Change 1 — `roxy-cache`: remove `from_request`

Delete `CacheKey::from_request` from `crates/roxy-cache/src/key.rs` along with
its unit test `from_request_picks_authority_from_uri`. `from_parts` becomes the
only public constructor.

After this change, `key.rs` no longer references `http::Request`. The
`roxy-cache` crate's `http` dependency stays (it is used elsewhere in the
crate), but the keying module stops knowing about HTTP request semantics. This
removes the entire class of "which host field did we pick" bugs from this
module.

### Change 2 — `roxy-proxy/handler.rs`: build the key explicitly

In `Handler::handle`, replace line 59:

```rust
// Before
let key = CacheKey::from_request(&req, &label, "https", &authority);

// After
let host_for_key = authority.to_ascii_lowercase();
let key = CacheKey::from_parts(
    &label,
    req.method().as_str(),
    "https",
    &host_for_key,
    req.uri().path(),
    req.uri().query(),
);

if let Some(client_host) = client_authority(&req) {
    if !authority_matches(&authority, &client_host) {
        tracing::warn!(
            connect_authority = %authority,
            client_host = %client_host,
            kind = "host_mismatch",
            "client Host/URI authority disagrees with CONNECT authority; \
             keying by CONNECT authority"
        );
    }
}
```

Helpers (private to `handler.rs`):

- `client_authority(&Request<_>) -> Option<String>` — returns the first of
  `req.uri().host().map(str::to_string)` or the `Host` header value (decoded
  as ASCII string). Returns `None` when neither is present.
- `authority_matches(connect: &str, client: &str) -> bool` — case-insensitive
  comparison after stripping a trailing default port (`:443`) from either side.
  Non-default ports compare strictly. IPv6 brackets are preserved as-is in the
  string comparison.

The CONNECT authority is passed verbatim to `from_parts` (lowercased). No
port-stripping is applied at the keying layer — the authority always arrives in
canonical `host:port` form from `read_connect`, so all requests for the same
logical resource produce the same key.

### Change 3 — tests

All in `crates/roxy-proxy/src/handler.rs`, in a new `#[cfg(test)]` module
alongside `label_tests`:

| Test | What it asserts |
|---|---|
| `cache_key_uses_connect_authority` | Request with `Host: attacker.com` + CONNECT authority `bank.com:443` produces a `CacheKey` equal to `from_parts(label, "GET", "https", "bank.com:443", "/", None)`, *not* one naming `attacker.com`. |
| `host_mismatch_emits_warning` | Same setup as above; assert a `host_mismatch`-kinded warning event was emitted. Capture via `tracing-subscriber` (already a workspace dep) using either `fmt().with_test_writer()` against an in-memory buffer, or a small custom `Layer` that records events into a `Mutex<Vec<…>>` — pick whichever is lowest-friction at implementation time. |
| `matching_host_does_not_warn` | Host header `bank.com` with CONNECT `bank.com:443` is treated as matching (default port stripped); no warning emitted. |

The deleted `from_request_picks_authority_from_uri` test in `key.rs` does not
need a replacement — its premise (URI host should influence the key) is now
incorrect.

If extracting the keying logic into a private free function in `handler.rs` is
required to make these tests construct a request and call the keying code
directly (without spinning up the full `Handler`), do so. Keep the function
private to the module.

## Side benefit

The port-normalization inconsistency described in "Secondary inconsistency"
above is resolved automatically: the handler always passes the CONNECT
authority verbatim to `from_parts`, so the same logical request always
produces the same key regardless of which fields the client populates.

## Migration risk

- **Only one production caller.** Verified by `grep -rn "CacheKey::from_request"`:
  the sole production callsite is `handler.rs:59`. The only other reference is
  the unit test that is being deleted.
- **Cached entries from before the change become unreachable.** This is
  intentional — those entries were keyed by attacker-controllable input. No
  data loss; the cache simply cold-starts for affected entries.
- **Edge case — bare CONNECT authority with no port.** RFC 7231 §4.3.6 requires
  CONNECT request-targets to include a port. If a malformed CONNECT line ever
  reached the handler with a bare host, `authority_matches` still behaves
  correctly via plain lowercased comparison. No special case needed.

## Out of this design

These are explicitly *not* changed by this work and remain open follow-ups if
they become problems:

- SNI vs CONNECT authority validation (would belong in `roxy-mitm` /
  `roxy-http/accept.rs`, not the cache layer).
- Validation that the Host header is a syntactically valid authority.
- Rejection (400) on Host mismatch — deferred per design discussion; revisit
  if log volume shows a meaningful rate of misbehaving clients.
