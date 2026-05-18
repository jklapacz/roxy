# Cache: respect Vary header (avoid serving wrong variant)

**Issue:** roxy-4y6
**Date:** 2026-05-17
**Status:** Design approved, awaiting plan

## Problem

`CacheKey::from_parts` (`crates/roxy-cache/src/key.rs`) composes the cache
key from `(profile, method, scheme, host, path, query)`. No request headers
participate. Responses are stored under that key alone and looked up the
same way.

This is wrong whenever the origin's response varies by request header. The
canonical case: a `GET /api` with `Accept: application/json` is cached;
a later `GET /api` with `Accept: text/html` finds the cached entry and
receives the JSON variant. Same shape applies to `Accept-Encoding`,
`Accept-Language`, and any header the origin declares in `Vary`.

The SQLite schema in `crates/roxy-cache-fs/src/index.rs` enforces this:
`PRIMARY KEY (key)` — one row per base key, no variant dimension.

`Vary: *` is also unhandled. Per RFC 9111 §4.1 that response is
unselectable by any subsequent request, so it must not be cached at all.

## Goals

1. Cache lookups respect any `Vary` header on the stored response. A request
   whose Vary-listed header values differ from a cached variant misses; a
   request whose values match hits.
2. Multiple variants under the same base key coexist (e.g., one JSON, one
   HTML row for the same URL).
3. `Vary: *` responses are not stored.
4. Existing call sites that don't care about Vary keep working with a small
   API addition, not a rewrite.

## Non-goals

- No `If-None-Match` / `If-Modified-Since` revalidation. That belongs with
  the broader cache-revalidation work that is already deferred.
- No header-value normalization beyond a straight byte compare. RFC 9110
  permits per-header semantic comparison; we don't do it. A request with
  `Accept: text/html, */*` and one with `Accept: */*, text/html` get
  separate variants. Acceptable for now.
- No bound on number of variants per base key. Pathological
  `Vary: User-Agent` against many UAs can grow unbounded. Tracked as a
  separate follow-up (variant cap / LRU eviction).
- No preservation of pre-upgrade cache entries. The old schema is dropped on
  first open; cache cold-starts. The local cache is cheap to rebuild.

## Design

Three crates change: `roxy-cache` (trait + types), `roxy-cache-fs` (schema +
selector logic), `roxy-proxy` (handler call sites + `Vary: *` short-circuit).

### Change 1 — `roxy-cache`: trait signature + variant selector type

The `Cache` trait gains request headers on both methods. To keep
`roxy-cache` free of the `http` crate (the existing pattern — see
`ResponseMeta::headers` using `Vec<(String, Vec<u8>)>`), headers are passed
as a borrowed slice of the same owned-pair shape:

```rust
pub type ReqHeaders = [(String, Vec<u8>)];

#[async_trait]
pub trait Cache: Send + Sync {
    async fn lookup(
        &self,
        key: &CacheKey,
        req_headers: &ReqHeaders,
    ) -> Result<Option<CachedResponse>, CacheError>;

    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
        default_ttl: std::time::Duration,
        req_headers: &ReqHeaders,
    ) -> Result<Box<dyn CacheWriter>, CacheError>;
}
```

The owned-pair shape lets the handler build the slice once, before moving
`req` into parts, and reuse it across both calls (lookup is before send,
`begin_store` is after).

A new module `roxy-cache/src/vary.rs` exposes:

```rust
/// Compute the variant selector for `(vary_header_value, req_headers)`.
/// Returns empty bytes when `vary_header_value` is None (no Vary on response).
/// Caller passes the raw Vary string verbatim (e.g. "Accept, Accept-Encoding").
pub fn compute_selector(vary: Option<&str>, req_headers: &ReqHeaders) -> Vec<u8>;
```

Algorithm:

1. If `vary` is `None` or empty after trim → return empty `Vec`.
2. Split on `,`, trim each name, lowercase each name. Drop empties.
3. For each name in sorted order: look up the request header (case-
   insensitive lookup over the `req_headers` slice). Missing → empty value.
4. Encode as `name\0value\0name\0value\0…` with a NUL terminator after the
   last pair.
5. SHA-256 the encoding. Return the 32-byte digest.

No special handling for `*` here — the proxy short-circuits before reaching
the cache (see Change 3).

### Change 2 — `roxy-cache-fs`: schema, migration, variant routing

**Schema (`index.rs`):**

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS entries (
    key            BLOB NOT NULL,
    vary_selector  BLOB NOT NULL,           -- empty bytes = no Vary
    vary_headers   TEXT NULL,               -- raw Vary value from response
    content_hash   BLOB NOT NULL,
    status         INTEGER NOT NULL,
    headers_json   TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    ttl_seconds    INTEGER NOT NULL,
    PRIMARY KEY (key, vary_selector)
);

CREATE INDEX IF NOT EXISTS entries_content_hash ON entries(content_hash);
```

**Migration:** `SCHEMA_VERSION` constant set to `2`. `index::open` reads
`PRAGMA user_version`; if it differs from `SCHEMA_VERSION`:

1. `DROP TABLE IF EXISTS entries` (entries metadata gone).
2. Wipe the `blobs/` subdirectory of the cache root — orphaned blobs from
   dropped entries would otherwise accumulate forever. The path is reachable
   via the same `cache_dir` the index lives under; pass it into `open`.
3. Recreate per the schema above.
4. `PRAGMA user_version = 2`.

Pre-existing cache contents are intentionally lost on upgrade — see Goals.

**FsCache::begin_store** parses `Vary` from `meta.headers` (case-insensitive
match on header name), passes it to `vary::compute_selector` together with
`req_headers`, and stores the resulting selector + the raw `Vary` value.
Empty/absent Vary → empty selector, `vary_headers = NULL`.

**FsCache::lookup** queries `SELECT … FROM entries WHERE key = ?1` returning
all rows. For each row in iteration order:

1. Compute `expected = vary::compute_selector(row.vary_headers.as_deref(),
   req_headers)`.
2. If `expected == row.vary_selector` (byte compare) and the row is not
   expired, return it.
3. Otherwise continue.

If no row matches → `Ok(None)`. Expired rows are skipped (not returned, not
deleted — eviction is a separate concern).

The typical case is 1–2 rows per base key. No additional index needed
beyond the composite primary key; SQLite will use it for the `WHERE key = ?`
prefix scan.

### Change 3 — `roxy-proxy`: `Vary: *` short-circuit + plumb request headers

`CacheDirectives` (`crates/roxy-proxy/src/cache_directives.rs`) gains a
`vary_star: bool` field. `should_cache()` becomes:

```rust
pub fn should_cache(&self) -> bool {
    !self.no_store && !self.private && !self.vary_star
}
```

Detection is folded into `parse()`: iterate `headers.get_all(http::header::VARY)`,
split each value on `,`, trim, and if any token equals `"*"`, set
`vary_star = true`. Done in `parse` (not a separate function) so callers
get a single `CacheDirectives` describing every reason caching might be
suppressed.

`Handler::handle_inner` (`crates/roxy-proxy/src/handler.rs`):

- Before the existing `self.cache.lookup(&key)` call: build a
  `Vec<(String, Vec<u8>)>` from `req.headers()` — one entry per header
  value (multi-valued headers contribute one entry per value, preserving
  iteration order). Same helper as `header_pairs` for response headers
  (which already exists in `handler.rs`). Pass the slice (`&req_headers`)
  to `lookup` and later to `begin_store`. Owning the pairs means the slice
  outlives the `req.into_parts()` move.
- The existing `parse(&resp_parts.headers)` call already sees `Vary` after
  this change; `cache_eligible` automatically excludes `Vary: *`.
- The `host_mismatch` warning logic is unchanged.

`build_cache_key_and_warn` is unchanged — the base key still doesn't
include headers. Variants live in the storage layer, not the key.

## Tests

### `roxy-cache` (new file `vary.rs` tests)

| Test | What it asserts |
|---|---|
| `no_vary_yields_empty_selector` | `compute_selector(None, &[])` returns empty `Vec`. |
| `same_headers_same_selector` | Two calls with the same headers produce equal digests. |
| `different_values_differ` | Differing `Accept` values produce different digests. |
| `vary_name_case_insensitive` | `Vary: Accept` matches `accept:` in the request slice. |
| `missing_request_header_is_empty` | Request without the Vary'd header is consistent (every absent value is "empty"); two such requests collide. |
| `comma_separated_and_multi_header_equivalent` | `Vary: A, B` produces the same selector as two Vary entries `A` then `B`. |
| `vary_names_sorted_before_hashing` | `Vary: B, A` and `Vary: A, B` produce the same selector. |

### `roxy-cache-fs` (extend `writer.rs` `#[cfg(test)]` module)

| Test | What it asserts |
|---|---|
| `vary_selector_round_trip` | Store with response `Vary: Accept` and request `Accept: application/json`. Lookup with the same request hits; lookup with `Accept: text/html` misses. |
| `two_variants_coexist` | Store JSON variant, then HTML variant under the same base key. Each lookup returns its own body; the SQLite table has two rows. |
| `no_vary_and_vary_can_coexist` | Store a no-Vary entry, then a `Vary: Accept` entry, same base key. A request with no `Accept` hits the no-Vary entry; a request with `Accept` matching the variant hits the variant. |
| `schema_v1_dropped_on_open` | Build a v1 `index.sqlite` inline (the old single-PK schema with `user_version = 0` or `1`), open it via `index::open`, confirm the row count is 0 afterward and the schema is the new shape. Also place a dummy file under `blobs/` and confirm the blob dir is wiped. |

### `roxy-proxy::cache_directives` (extend existing tests)

| Test | What it asserts |
|---|---|
| `vary_star_blocks_caching` | `Vary: *` → `should_cache()` is false. |
| `vary_named_header_still_cacheable` | `Vary: Accept` → `should_cache()` true (variants handled downstream). |
| `vary_star_among_named_still_blocks` | `Vary: *, Accept` → `should_cache()` false. RFC 9111 §4.1: `*` wins. |
| `vary_star_case_insensitive` | `vary: *` (lowercase header name) — `HeaderMap` already normalizes; assert the parser sees it. |

### `roxy-proxy/tests/cache_vary.rs` (new integration file, modeled on `cache_control.rs`)

| Test | What it asserts |
|---|---|
| `different_accept_get_different_responses` | Origin returns `Vary: Accept` with body tied to the `Accept` value. Two sequential requests with different `Accept` get their own bodies. |
| `same_accept_hits_cache` | Same `Accept` twice in a row → second request is a cache hit (origin counter does not advance). |
| `vary_star_not_cached` | Origin returns `Vary: *`. Two sequential requests both reach the origin (counter advances both times). |

### Regression

All existing tests in `roxy-cache-fs` (`writer.rs`) and `roxy-proxy`
(`cache_control.rs`) continue to pass after the API change. The migration:
update every call site to pass either `&[]` for tests that don't exercise
Vary, or a derived `&[(&str, &[u8])]` slice for tests that do.

## Call-site impact

`CacheKey::from_parts` keeps its current signature. Only `Cache::lookup`
and `Cache::begin_store` grow a `req_headers` parameter. Direct callers:

- `crates/roxy-proxy/src/handler.rs` — two call sites updated to build and
  pass the request-header slice.
- `crates/roxy-cache-fs/src/writer.rs` test module — store/lookup helpers
  pass `&[]` where Vary is not under test.

No other crates depend on the `Cache` trait surface. Verified by
`grep -rn "Cache::lookup\|Cache::begin_store\|\.lookup(\|\.begin_store(" crates/`.

## Migration risk

- **All pre-upgrade cache entries become unreachable on first open.** This
  is the explicit choice (cache cold-start is cheap; migration code carries
  carrying-cost). Documented above. No data loss in any operational sense.
- **Blob directory wipe on schema mismatch is destructive.** Bounded by the
  same `cache_dir` the index lives under; cannot touch anything else.
- **Request header copy cost.** The handler now allocates a
  `Vec<(String, Vec<u8>)>` from `req.headers()` on every request, even when
  the cache is disabled. Small (typically <20 headers); not a hot-path
  concern, but flagged for completeness.

## Out of this design

Follow-ups, intentionally not in scope:

- Variant cap / LRU per base key (`Vary: User-Agent` blow-up).
- Per-header semantic value comparison (`Accept` token reordering equivalence).
- Surfacing variant counts in telemetry.
- Eviction of expired rows (current behavior of skipping-but-not-deleting
  is preserved).
