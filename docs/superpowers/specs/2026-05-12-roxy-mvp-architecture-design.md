# Roxy MVP — Architecture Design

**Status:** Draft
**Date:** 2026-05-12
**Author:** Jakub Klapacz (with Claude)

## 1. Overview

Roxy is a caching HTTP forward proxy written in Rust. This document specifies the MVP scope: an HTTPS-capable proxy that performs man-in-the-middle TLS interception and caches origin responses at the content level, supporting HTTP/1.1 and HTTP/2 on both client and upstream sides.

The MVP is deliberately narrow. Several features advertised in the project README are deferred to follow-up specs:

- TLS / HTTP/2 fingerprint emulation (JA3, JA4, Akamai)
- Configurable cache key heuristics (per-host rules, header allow/deny lists)
- Upstream proxy chaining (residential proxy rotation)
- HTTP/3 / QUIC
- `Vary` header semantics
- Range requests / partial content
- Standards-compliant HTTP caching (`Cache-Control`, `ETag` revalidation)
- Shared cache backend implementations (Redis, S3)

## 2. Use case

Roxy is built for **web scraping / data collection at scale**, deployed as a sidecar to a scraper process on the same host. The driving value is twofold:

1. Reduce duplicate origin requests during repeated scrapes (cost, rate-limit pressure).
2. Provide a deterministic replay layer during scraper development.

Future fingerprint-emulation work targets the same use case, but is sequenced after the data plane is solid.

## 3. Goals and non-goals

### Goals

- Accept HTTPS proxy traffic from co-located scrapers via HTTP `CONNECT`.
- Decrypt TLS using a locally-generated CA and minted leaf certificates.
- Forward requests to origin over HTTP/1.1 or HTTP/2 (ALPN-negotiated).
- Cache complete response bodies with a content-addressable layout.
- Serve cached responses on subsequent identical requests within TTL.
- Never panic, never serve a corrupted cache entry, never fail a request because the cache failed.

### Non-goals (MVP)

- Standards-compliant HTTP caching semantics.
- Anti-bot or fingerprint-defeating behavior.
- Distributed operation, multi-tenancy, or authentication.
- Production-grade observability beyond structured logs.

## 4. Architecture

### 4.1 Top-level shape

```
┌─────────────┐    ┌──────────────────────────────────────────┐    ┌────────┐
│   scraper   │ ─▶ │                  roxy                    │ ─▶ │ origin │
└─────────────┘    │                                          │    └────────┘
   HTTP CONNECT    │  ┌────────┐  ┌────────┐  ┌────────────┐  │
   (h1)            │  │ accept │─▶│  MITM  │─▶│  HTTP svc  │  │
                   │  └────────┘  │ (CA +  │  │  (h1 + h2) │  │
                   │              │ certs) │  │            │  │
                   │              └────────┘  └─────┬──────┘  │
                   │                                │         │
                   │              ┌─────────────────▼──────┐  │
                   │              │     cache layer        │  │
                   │              │  trait: Cache          │  │
                   │              │   ├─ lookup(key)       │  │
                   │              │   └─ begin_store(...)  │  │
                   │              └────────┬───────────────┘  │
                   │                       │                  │
                   │              ┌────────▼───────┐          │
                   │              │ local backend  │          │
                   │              │ • sqlite index │          │
                   │              │ • fs blobs CAS │          │
                   │              └────────────────┘          │
                   │                       │ (miss)           │
                   │              ┌────────▼───────┐          │
                   │              │ upstream client│          │
                   │              │ hyper + rustls │          │
                   │              │  (h1/h2 ALPN)  │          │
                   │              └────────────────┘          │
                   └──────────────────────────────────────────┘
```

### 4.2 Crates

A cargo workspace with five small crates plus one binary crate. Workspace layout keeps modules independently buildable and testable and makes the cache-backend seam concrete:

| Crate | Purpose |
|---|---|
| `roxy-proxy` | Binary. CLI entry, config load, top-level wire-up. |
| `roxy-http` | HTTP accept loop, CONNECT handling, h1/h2 server + client (hyper). |
| `roxy-mitm` | CA management, leaf cert minting, TLS terminator (rustls + rcgen). |
| `roxy-cache` | `Cache` trait, key derivation, response types. Pure interface crate. |
| `roxy-cache-fs` | Filesystem + sqlite implementation of `Cache`. Only impl in MVP. |
| `roxy-config` | Typed TOML config loader. |

### 4.3 Approach and alternatives considered

The data plane is built on **`hyper` (server + client) + `rustls` + custom MITM glue**. CONNECT is handled by upgrading the connection, then a leaf cert is minted on the fly, a rustls server-side handshake runs on the upgraded stream, and hyper serves the negotiated protocol on the decrypted bytes.

The alternative considered was the `hudsucker` crate, which bundles CONNECT handling and the TLS rebridge. It was rejected because future fingerprint emulation requires direct control over the TLS ClientHello and HTTP/2 frame layer, neither of which hudsucker exposes. Adopting it now would mean ripping it out within a year. The extra code in approach A is mostly straightforward glue that pays for itself as soon as fingerprinting work begins.

### 4.4 Deployment

Single-process binary, listening on a configurable TCP port (default `127.0.0.1:8080`). The `Cache` trait is designed so a future shared backend (Redis, S3) can drop in without restructuring the data plane.

## 5. Request lifecycle

For an HTTPS `GET` sent through Roxy by a scraper:

```
1.  Client opens TCP to roxy:8080
2.  Client sends:   CONNECT example.com:443 HTTP/1.1
3.  Roxy replies:   HTTP/1.1 200 Connection Established
4.  Roxy mints leaf cert for "example.com" signed by Roxy CA
       └─ in-memory LRU keyed by SNI to avoid re-minting per request
5.  Roxy runs rustls server handshake on the upgraded socket
       └─ ALPN: advertises h2 + http/1.1
6.  After handshake → an h1-or-h2 hyper Server speaks on decrypted bytes
7.  Client sends:   GET /api/foo  +  headers
8.  Roxy computes cache key:   "GET https://example.com/api/foo"
9.  Cache.lookup(key):
       ├─ HIT and not expired  → reconstruct response from index + blob, return
       ├─ HIT but expired       → treat as miss (no revalidation in MVP)
       └─ MISS                  → step 10
10. Roxy opens hyper client to example.com:443 over rustls (ALPN: h2,h1)
11. Roxy forwards the request, streams the response body while:
       ├─ hashing incrementally (sha256)
       └─ buffering to a temp file (cache_dir/tmp/<uuid>)
12. After body end:
       ├─ rename temp file to cache_dir/blobs/<sha256[0:2]>/<sha256>.bin
       ├─ insert/replace row in sqlite: (key, content_hash, status, headers_json, ts, ttl)
       └─ tee response back to client (do not store-then-forward)
13. Connection keepalive per protocol rules
```

### 5.1 Tee vs store-then-forward

The proxy streams the body to the client and to the cache writer simultaneously. Store-then-forward would inflate latency by the full origin-fetch time on every miss. Tee adds one wrinkle: if the client disconnects mid-stream, Roxy continues draining the upstream body up to a cap so the cache write completes. Beyond the cap, the write is aborted and the temp file discarded.

### 5.2 Cert minting cache

Re-minting on every CONNECT would burn CPU and produce a different cert serial per request, which some clients dislike. Leaf certs are kept in an in-memory LRU keyed by SNI (default 10000 entries) and minted lazily.

## 6. Cache design

### 6.1 Cache key

The MVP cache key is derived from the request as a deterministic byte string:

```
{method}\n{scheme}\n{host}\n{path}\n{sorted query string}
```

Query parameters are sorted by name. `?b=2&a=1` and `?a=1&b=2` hit the same entry. The rare API that semantically cares about parameter order will see false hits, which is acceptable for MVP; a per-host opt-out lands with the configurable-key spec.

Method, scheme, host, and path are taken verbatim from the decrypted request line. Request bodies and headers are not part of the key in MVP.

### 6.2 Content-addressable storage

- **Blobs:** `<cache_dir>/blobs/<sha256[0:2]>/<sha256>.bin` — raw response body bytes.
- **Index:** sqlite database at `<cache_dir>/index.sqlite`:

```sql
CREATE TABLE entries (
  key          BLOB PRIMARY KEY,
  content_hash BLOB NOT NULL,
  status       INTEGER NOT NULL,
  headers_json TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  ttl_seconds  INTEGER NOT NULL
);

CREATE INDEX entries_content_hash ON entries(content_hash);
```

Identical bodies across keys share a blob. In MVP, blobs are never garbage-collected — disk is cheap and a separate cleanup spec will introduce a refcount or sweep job.

### 6.3 TTL and freshness

A single global `default_ttl_seconds` from config governs all entries. Origin `Cache-Control` is ignored. Expired entries are treated as misses and overwritten on the next fetch; no revalidation in MVP.

### 6.4 `Cache` trait

```rust
#[async_trait]
pub trait Cache: Send + Sync {
    async fn lookup(&self, key: &CacheKey) -> Result<Option<CachedResponse>, CacheError>;

    /// Returns a body-sink the proxy streams the upstream response into.
    /// On `finish()` the entry is committed atomically.
    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
    ) -> Result<Box<dyn CacheWriter>, CacheError>;
}

pub trait CacheWriter: AsyncWrite + Send {
    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(), CacheError>>;
    fn abort(self: Box<Self>);
}
```

The streaming-writer shape makes tee-while-caching possible without forcing the full body into memory and is satisfiable by future `RedisCache` (buffer to memory) or `S3Cache` (multipart upload) implementations.

## 7. MITM design

### 7.1 Certificate authority

- Generated on first run if absent: 4096-bit RSA cert and key written to `<ca_dir>/roxy-ca.{crt,key}`.
- Validity: 10 years.
- The user must install `roxy-ca.crt` in their client's trust store. MVP prints the path and a short hint at startup. A `roxy ca install` helper command is a future affordance.

### 7.2 Leaf certificates

- Minted lazily on first SNI hit. 2048-bit RSA. 24-hour validity. SAN set to the SNI value.
- In-memory LRU keyed by SNI, default 10000 entries.
- Re-minted on eviction or process restart. Minting cost is ~ms.

### 7.3 TLS interception flow

1. Accept `CONNECT`.
2. Reply `HTTP/1.1 200 Connection Established`.
3. Look up or mint a leaf cert for the SNI host.
4. Run a rustls server handshake on the upgraded socket. ALPN: `h2,http/1.1`.
5. Hyper serves the negotiated protocol on the decrypted byte stream.

## 8. Upstream client

`hyper` + `hyper-rustls`. ALPN advertises `h2,http/1.1`; protocol is negotiated per connection. The connection pool reuses TCP+TLS connections per `(host, port, alpn)` triple. Default pool size 32 idle per host, 300s idle timeout. Upstream cert validation uses rustls' built-in roots; there is no skip-verify knob in MVP.

## 9. Configuration

TOML at a path specified by `--config <path>` (default `$XDG_CONFIG_HOME/roxy/config.toml`).

```toml
listen = "127.0.0.1:8080"

[cache]
dir = "~/.local/share/roxy/cache"
default_ttl_seconds = 3600

[ca]
dir = "~/.config/roxy/ca"

[log]
level = "info"
```

No per-host overrides, no upstream proxies, no header allowlists. All deferred.

## 10. Error handling

The proxy is on the data path, so it must never panic and never make a corrupted cache entry visible.

| Class | Behavior |
|---|---|
| Origin returns 5xx, refuses connection, or fails TLS handshake | Forwarded as-is to the client. **Not cached.** |
| Client disconnects mid-stream | Continue draining upstream body up to 50 MB beyond the disconnect point so the cache write completes. Past the cap, abort and discard. |
| Cache backend failure (sqlite locked, disk full, fs error) | Log and serve as pass-through. The request must succeed if the origin is reachable. |
| Partial write crash | Blob is written to `tmp/<uuid>` and atomically renamed only after the full body hashes successfully. The sqlite row is inserted in the same transaction as the rename. Orphan temp files are cleaned at startup. |
| Upstream cert validation failure | Return `502 Bad Gateway` to the client. |
| Internal panic | `#![deny(clippy::unwrap_used, clippy::expect_used)]` in production code. The accept loop has a top-level catch that logs and drops the connection rather than tearing down the process. |

## 11. Testing strategy

Three layers, lightest at the top.

1. **Unit tests** in each crate. Targets: cache key derivation, sqlite schema migrations, cert minting determinism, LRU eviction, query-string sorting.
2. **Integration tests** in `roxy-proxy/tests/`. A real Roxy on a random port, a `reqwest` client pointing at it, and an in-process `axum`-based fake origin. Cases: golden path (miss → store → hit), tee correctness, TTL expiry, origin error pass-through, client disconnect mid-body, large-body cap behavior.
3. **Smoke test** against a public endpoint (e.g., `https://httpbin.org/anything`), gated behind `#[ignore]` so CI doesn't depend on the internet.

Out of scope for MVP testing: load tests, HTTP parser fuzzing (hyper handles this), property-based testing of cache semantics.

## 12. Known limits in MVP

Each of the below is acceptable for MVP and is a candidate follow-up spec.

- No size cap on cached bodies; truly huge responses can fill disk.
- No deduplication of concurrent identical misses; two simultaneous requests for the same key both fetch and race on cache write.
- Sqlite single-writer constraint; under high concurrent miss volume, the index can become a bottleneck.
- CA install is manual; no helper command.
- No metrics, no admin endpoint.
- No cache eviction or blob garbage collection; cache size grows monotonically until manually pruned.

## 13. Sequencing

Implementation will be tracked in beads. The natural order is:

1. Workspace scaffolding.
2. `roxy-config`, `roxy-cache` trait, `roxy-mitm` (independent, parallelizable).
3. `roxy-cache-fs` (depends on `roxy-cache`).
4. `roxy-http` accept loop and CONNECT handler (depends on `roxy-mitm`).
5. `roxy-http` upstream client (independent of the accept loop).
6. Tee-while-caching response handling (depends on cache + http).
7. `roxy-proxy` binary wire-up (depends on all above).
8. Integration test harness.
9. Smoke test.
