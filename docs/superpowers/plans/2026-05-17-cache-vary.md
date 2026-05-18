# Cache: respect Vary header — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cache lookups respect the response `Vary` header so requests with different Vary'd header values do not cross-serve, and `Vary: *` responses are not cached.

**Architecture:** Storage migrates to a composite `(key, vary_selector)` primary key. A new free function `roxy_cache::vary::compute_selector` hashes the request's Vary'd header values into a 32-byte selector (empty bytes when the response had no `Vary`). The `Cache` trait grows a `req_headers` parameter on both `lookup` and `begin_store`. `CacheDirectives` gains a `vary_star` flag that makes `should_cache()` return false for `Vary: *` responses.

**Tech Stack:** Rust workspace, `rusqlite`, `sha2`, `tokio`, `axum` (test fixture). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-05-17-cache-vary-design.md`. **Issue:** roxy-4y6.

**File map (touched in this plan):**

| File | Role |
|---|---|
| `crates/roxy-proxy/src/cache_directives.rs` | Add `vary_star` field + Vary parsing; update `should_cache`. |
| `crates/roxy-cache/src/vary.rs` *(new)* | `compute_selector` free function + unit tests. |
| `crates/roxy-cache/src/lib.rs` | Export `vary` module + `ReqHeaders` alias; change `Cache` trait signature. |
| `crates/roxy-cache-fs/src/index.rs` | Schema v2: composite PK, migration drop-and-recreate, blob-dir wipe. |
| `crates/roxy-cache-fs/src/writer.rs` | `FsCache::lookup` + `begin_store` + `FsWriter::finish` use selector and `vary_headers`. |
| `crates/roxy-proxy/src/handler.rs` | Build `Vec<(String, Vec<u8>)>` from `req.headers()`, pass to cache calls. |
| `crates/roxy-proxy/tests/common/mod.rs` | Add `/vary` route to fake origin. |
| `crates/roxy-proxy/tests/cache_vary.rs` *(new)* | Integration tests for variant routing + `Vary: *`. |

---

## Task 1: `CacheDirectives.vary_star`

Adds Vary-* short-circuit in `CacheDirectives::should_cache`. Pure addition — no API surface changes. Independent of every other task.

**Files:**
- Modify: `crates/roxy-proxy/src/cache_directives.rs`

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` block in `crates/roxy-proxy/src/cache_directives.rs`:

```rust
    #[test]
    fn vary_star_blocks_caching() {
        let mut h = http::HeaderMap::new();
        h.append(http::header::VARY, http::HeaderValue::from_static("*"));
        let d = parse(&h);
        assert!(d.vary_star);
        assert!(!d.should_cache());
    }

    #[test]
    fn vary_named_header_still_cacheable() {
        let mut h = http::HeaderMap::new();
        h.append(http::header::VARY, http::HeaderValue::from_static("Accept"));
        let d = parse(&h);
        assert!(!d.vary_star);
        assert!(d.should_cache());
    }

    #[test]
    fn vary_star_among_named_still_blocks() {
        let mut h = http::HeaderMap::new();
        h.append(
            http::header::VARY,
            http::HeaderValue::from_static("Accept, *"),
        );
        let d = parse(&h);
        assert!(d.vary_star);
        assert!(!d.should_cache());
    }

    #[test]
    fn vary_star_across_multiple_header_lines() {
        let mut h = http::HeaderMap::new();
        h.append(http::header::VARY, http::HeaderValue::from_static("Accept"));
        h.append(http::header::VARY, http::HeaderValue::from_static(" * "));
        let d = parse(&h);
        assert!(d.vary_star);
    }
```

- [ ] **Step 2: Run tests, confirm they fail**

```
cargo test -p roxy-proxy --lib cache_directives::tests::vary
```

Expected: four test failures (the `vary_star` field does not exist).

- [ ] **Step 3: Add `vary_star` to the struct**

Edit `crates/roxy-proxy/src/cache_directives.rs`, replace the existing struct definition with:

```rust
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CacheDirectives {
    pub no_store: bool,
    pub private: bool,
    pub vary_star: bool,
    pub max_age: Option<Duration>,
}
```

- [ ] **Step 4: Update `should_cache`**

Replace the existing `should_cache` method body with:

```rust
    pub fn should_cache(&self) -> bool {
        !self.no_store && !self.private && !self.vary_star
    }
```

- [ ] **Step 5: Parse `Vary` in `parse`**

At the bottom of the `parse` function body (after the existing `for value in headers.get_all(http::header::CACHE_CONTROL)` loop), append:

```rust
    for value in headers.get_all(http::header::VARY).iter() {
        let s = match value.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        for raw in s.split(',') {
            if raw.trim() == "*" {
                out.vary_star = true;
            }
        }
    }
```

- [ ] **Step 6: Run new tests + existing tests, confirm all pass**

```
cargo test -p roxy-proxy --lib cache_directives
```

Expected: all green, including pre-existing tests.

- [ ] **Step 7: Commit**

```
git add crates/roxy-proxy/src/cache_directives.rs
git commit -m "feat(roxy-proxy): treat Vary: * as uncacheable (roxy-4y6)"
```

---

## Task 2: `roxy_cache::vary::compute_selector`

New free function that computes a SHA-256 variant selector. No dependency on the `http` crate. Standalone — does not require trait or schema changes.

**Files:**
- Create: `crates/roxy-cache/src/vary.rs`
- Modify: `crates/roxy-cache/src/lib.rs` (module declaration + re-export)
- Modify: `crates/roxy-cache/Cargo.toml` (add `sha2` if not present)

- [ ] **Step 1: Check `sha2` dependency**

```
grep '^sha2' crates/roxy-cache/Cargo.toml
```

If no match, add `sha2 = { workspace = true }` (mirroring `crates/roxy-cache-fs/Cargo.toml`) under `[dependencies]`. If `sha2` is not in the workspace `Cargo.toml` `[workspace.dependencies]`, use the exact version pinned by `crates/roxy-cache-fs/Cargo.toml`.

- [ ] **Step 2: Write the failing tests**

Create `crates/roxy-cache/src/vary.rs` with the test module only (tests fail at compile time because `compute_selector` does not yet exist):

```rust
//! Variant selector hashing for response `Vary` headers. The selector is
//! the SHA-256 of a stable encoding of `(header-name, header-value)` pairs
//! for the request headers named in the response's `Vary`. When the
//! response had no `Vary`, the selector is the empty byte slice — so
//! no-Vary entries collide only with other no-Vary entries for the same
//! base key.

pub type ReqHeaders = [(String, Vec<u8>)];

pub fn compute_selector(_vary: Option<&str>, _req_headers: &ReqHeaders) -> Vec<u8> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect()
    }

    #[test]
    fn no_vary_yields_empty_selector() {
        assert!(compute_selector(None, &[]).is_empty());
        assert!(compute_selector(Some("   "), &[]).is_empty());
        assert!(compute_selector(Some(""), &[]).is_empty());
    }

    #[test]
    fn same_headers_same_selector() {
        let req = pairs(&[("accept", b"application/json")]);
        let a = compute_selector(Some("Accept"), &req);
        let b = compute_selector(Some("Accept"), &req);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn different_values_differ() {
        let json = pairs(&[("accept", b"application/json")]);
        let html = pairs(&[("accept", b"text/html")]);
        assert_ne!(
            compute_selector(Some("Accept"), &json),
            compute_selector(Some("Accept"), &html)
        );
    }

    #[test]
    fn vary_name_case_insensitive() {
        let lower = pairs(&[("accept", b"application/json")]);
        let upper = pairs(&[("Accept", b"application/json")]);
        assert_eq!(
            compute_selector(Some("Accept"), &lower),
            compute_selector(Some("accept"), &upper),
        );
    }

    #[test]
    fn missing_request_header_is_empty_value() {
        // Both requests are missing the Vary'd header, so they should collide.
        let a = compute_selector(Some("Accept-Encoding"), &[]);
        let b = compute_selector(Some("Accept-Encoding"), &pairs(&[("user-agent", b"x")]));
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // A present header should produce a different selector than absent.
        let c = compute_selector(
            Some("Accept-Encoding"),
            &pairs(&[("accept-encoding", b"gzip")]),
        );
        assert_ne!(a, c);
    }

    #[test]
    fn comma_separated_and_multi_value_equivalent() {
        let req = pairs(&[("accept", b"application/json"), ("accept-encoding", b"gzip")]);
        let combined = compute_selector(Some("Accept, Accept-Encoding"), &req);
        let with_spaces = compute_selector(Some(" Accept , Accept-Encoding "), &req);
        assert_eq!(combined, with_spaces);
    }

    #[test]
    fn vary_names_sorted_before_hashing() {
        let req = pairs(&[("a", b"1"), ("b", b"2")]);
        assert_eq!(
            compute_selector(Some("A, B"), &req),
            compute_selector(Some("B, A"), &req)
        );
    }

    #[test]
    fn multiple_request_values_for_same_header_join_with_comma() {
        // If the request slice carries the same Vary'd header twice (multi-value
        // header), both contribute to the selector. The function joins them in
        // slice order with a comma so duplicates are not silently dropped.
        let one = pairs(&[("accept", b"application/json")]);
        let two = pairs(&[("accept", b"application/json"), ("accept", b"text/html")]);
        assert_ne!(
            compute_selector(Some("Accept"), &one),
            compute_selector(Some("Accept"), &two)
        );
    }
}
```

- [ ] **Step 3: Register the module in `lib.rs`**

Edit `crates/roxy-cache/src/lib.rs`. Add `mod vary;` next to the other `mod` declarations near the top. Add a re-export `pub use vary::{compute_selector, ReqHeaders};` next to the existing `pub use`s.

- [ ] **Step 4: Run tests, confirm they fail**

```
cargo test -p roxy-cache --lib vary::tests
```

Expected: most tests fail (the stub returns empty, so length checks and inequality checks fail).

- [ ] **Step 5: Implement `compute_selector`**

Replace the stub in `crates/roxy-cache/src/vary.rs`:

```rust
use sha2::{Digest, Sha256};

pub type ReqHeaders = [(String, Vec<u8>)];

/// Compute a 32-byte variant selector for the request headers named in the
/// response's `Vary`. Returns an empty `Vec` when `vary` is `None` or empty
/// (so no-Vary entries collide only with other no-Vary entries).
///
/// Algorithm: split `vary` on `,`, trim and lowercase each name, drop
/// empties and any `*` token (Vary: * is filtered out upstream). Sort the
/// names ASCII-ascending. For each name, gather every matching request
/// header value (case-insensitive name compare) joined by ASCII comma. A
/// missing request header contributes an empty value. Encode as
/// `name\0value\0name\0value\0…` and SHA-256-hash the encoding.
pub fn compute_selector(vary: Option<&str>, req_headers: &ReqHeaders) -> Vec<u8> {
    let Some(vary) = vary else {
        return Vec::new();
    };
    let mut names: Vec<String> = vary
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != "*")
        .collect();
    if names.is_empty() {
        return Vec::new();
    }
    names.sort();
    names.dedup();

    let mut hasher = Sha256::new();
    for name in &names {
        hasher.update(name.as_bytes());
        hasher.update([0u8]);

        let mut first = true;
        for (req_name, req_value) in req_headers {
            if req_name.eq_ignore_ascii_case(name) {
                if !first {
                    hasher.update(b",");
                }
                hasher.update(req_value);
                first = false;
            }
        }
        hasher.update([0u8]);
    }
    hasher.finalize().to_vec()
}
```

- [ ] **Step 6: Run tests, confirm all pass**

```
cargo test -p roxy-cache --lib vary::tests
```

Expected: all green.

- [ ] **Step 7: Commit**

```
git add crates/roxy-cache/src/vary.rs crates/roxy-cache/src/lib.rs crates/roxy-cache/Cargo.toml
git commit -m "feat(roxy-cache): add Vary selector hashing (roxy-4y6)"
```

---

## Task 3: Schema v2 migration

Migrates `roxy-cache-fs` to the composite `(key, vary_selector)` primary key with two new columns, plus blob-dir wipe on schema mismatch. `lookup`/`begin_store` semantics do not change yet — every entry stores an empty selector and `NULL` Vary headers. Existing `writer.rs` tests must continue to pass.

**Files:**
- Modify: `crates/roxy-cache-fs/src/index.rs`
- Modify: `crates/roxy-cache-fs/src/writer.rs` (insert + select pick up two new columns; default empty selector for now)

- [ ] **Step 1: Write the failing migration test**

Append to `#[cfg(test)] mod tests` in `crates/roxy-cache-fs/src/index.rs`:

```rust
    #[test]
    fn opens_existing_v1_db_drops_table_and_wipes_blobs() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        let db = cache_dir.join("index.sqlite");

        // Build a v1 DB inline.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "PRAGMA user_version = 1;
                 CREATE TABLE entries (
                    key BLOB PRIMARY KEY,
                    content_hash BLOB NOT NULL,
                    status INTEGER NOT NULL,
                    headers_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    ttl_seconds INTEGER NOT NULL
                 );
                 INSERT INTO entries
                   VALUES (X'0102', X'aa', 200, '[]', 0, 60);",
            )
            .unwrap();
        }
        // Place a stray blob to confirm the wipe.
        let blobs = cache_dir.join("blobs/aa");
        fs::create_dir_all(&blobs).unwrap();
        fs::write(blobs.join("orphan.bin"), b"x").unwrap();

        // Open with the new code path.
        let conn = open(&db, &cache_dir).unwrap();

        // Schema is now v2 and the table is empty.
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM entries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);

        // The columns we will need next exist.
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(entries)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(cols.contains(&"vary_selector".to_string()));
        assert!(cols.contains(&"vary_headers".to_string()));

        // The stray blob directory is gone.
        assert!(!cache_dir.join("blobs").exists());
    }

    #[test]
    fn opens_fresh_db_at_v2() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        let db = cache_dir.join("index.sqlite");
        let conn = open(&db, &cache_dir).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2);
    }
```

Also update the existing `opens_and_creates_schema` test to pass the new second argument:

```rust
    #[test]
    fn opens_and_creates_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("idx.sqlite");
        let conn = open(&db, dir.path()).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'entries'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }
```

- [ ] **Step 2: Run tests, confirm they fail**

```
cargo test -p roxy-cache-fs --lib index
```

Expected: compile error — `open` currently takes one argument. After fixing the call sites in writer.rs (next step) it will fail behaviorally.

- [ ] **Step 3: Rewrite `index::open` and `SCHEMA_V1`**

Replace the entire body of `crates/roxy-cache-fs/src/index.rs` (above the `#[cfg(test)]`) with:

```rust
use rusqlite::Connection;
use std::path::Path;

const SCHEMA_VERSION: i64 = 2;

const SCHEMA_V2: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS entries (
    key            BLOB NOT NULL,
    vary_selector  BLOB NOT NULL,
    vary_headers   TEXT NULL,
    content_hash   BLOB NOT NULL,
    status         INTEGER NOT NULL,
    headers_json   TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    ttl_seconds    INTEGER NOT NULL,
    PRIMARY KEY (key, vary_selector)
);

CREATE INDEX IF NOT EXISTS entries_content_hash ON entries(content_hash);
"#;

/// Open the cache index, applying migrations as needed.
///
/// `cache_dir` is used during migration to wipe the `blobs/` subdirectory
/// when the on-disk schema version does not match `SCHEMA_VERSION`. Doing
/// the wipe here keeps it cosited with the schema change so blob orphans
/// can never outlive the entries that reference them.
pub fn open(db_path: &Path, cache_dir: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(db_path)?;
    let on_disk: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if on_disk != SCHEMA_VERSION {
        conn.execute_batch("DROP TABLE IF EXISTS entries")?;
        // Best-effort blob wipe. Failures (e.g. missing dir) are non-fatal —
        // the next call to `ensure_dirs` will recreate the layout.
        let _ = std::fs::remove_dir_all(cache_dir.join("blobs"));
    }
    conn.execute_batch(SCHEMA_V2)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(conn)
}
```

- [ ] **Step 4: Update `FsCache::open` to pass `cache_dir`**

Edit `crates/roxy-cache-fs/src/writer.rs`. Find the `FsCache::open` method (around line 24) and update the `index::open` call from:

```rust
        let conn = index::open(&cache_dir.join("index.sqlite"))
            .map_err(|e| CacheError::Backend(e.to_string()))?;
```

to:

```rust
        let conn = index::open(&cache_dir.join("index.sqlite"), &cache_dir)
            .map_err(|e| CacheError::Backend(e.to_string()))?;
```

(Note: `ensure_dirs(&cache_dir)` is called before `index::open`, but `index::open` may wipe `blobs/`. That is fine — `ensure_dirs` runs once at startup before any blobs are written; if the wipe happens, the next blob write recreates the directory via the writer's existing `tokio::fs::create_dir_all` path. Verify by searching `writer.rs` for `create_dir_all` and confirming the path is rebuilt at write time.)

- [ ] **Step 5: Move `ensure_dirs` to run after `index::open`**

To prevent the wipe from destroying directories that `ensure_dirs` just created, reorder the body of `FsCache::open` so that `index::open` runs first, then `ensure_dirs`. Final shape:

```rust
    pub fn open(cache_dir: impl Into<PathBuf>) -> Result<Self, CacheError> {
        let cache_dir = cache_dir.into();
        let conn = index::open(&cache_dir.join("index.sqlite"), &cache_dir)
            .map_err(|e| CacheError::Backend(e.to_string()))?;
        ensure_dirs(&cache_dir).map_err(CacheError::Io)?;
        Ok(Self {
            cache_dir,
            conn: Arc::new(Mutex::new(conn)),
        })
    }
```

But `index::open` itself needs the parent dir for `index.sqlite` to exist — SQLite's `Connection::open` does not create parent dirs. So before `index::open`, also call `std::fs::create_dir_all(&cache_dir)` directly (idempotent, cheap):

```rust
    pub fn open(cache_dir: impl Into<PathBuf>) -> Result<Self, CacheError> {
        let cache_dir = cache_dir.into();
        std::fs::create_dir_all(&cache_dir).map_err(CacheError::Io)?;
        let conn = index::open(&cache_dir.join("index.sqlite"), &cache_dir)
            .map_err(|e| CacheError::Backend(e.to_string()))?;
        ensure_dirs(&cache_dir).map_err(CacheError::Io)?;
        Ok(Self {
            cache_dir,
            conn: Arc::new(Mutex::new(conn)),
        })
    }
```

- [ ] **Step 6: Update writer INSERT to populate new columns**

Find the `INSERT OR REPLACE INTO entries` statement in `FsWriter::finish` (around line 137). Replace it with:

```rust
            conn.execute(
                "INSERT OR REPLACE INTO entries
                   (key, vary_selector, vary_headers, content_hash, status, headers_json, created_at, ttl_seconds)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    self.key.as_bytes(),
                    Vec::<u8>::new(),    // empty selector (real selector lands in Task 5)
                    Option::<String>::None,
                    hash.as_slice(),
                    self.meta.status as i64,
                    headers_json,
                    now,
                    self.ttl.as_secs() as i64,
                ],
            )
```

- [ ] **Step 7: Update `FsCache::lookup` SELECT**

Find the `query_row` in `FsCache::lookup` (around line 170). Update its SQL to filter by the empty selector explicitly so that lookups remain deterministic across rows after Task 5 adds variants:

```rust
            conn.query_row(
                "SELECT content_hash, status, headers_json, created_at, ttl_seconds
                 FROM entries WHERE key = ?1 AND vary_selector = ?2",
                rusqlite::params![key.as_bytes(), Vec::<u8>::new()],
                |r| {
                    let content_hash: Vec<u8> = r.get(0)?;
                    let status: i64 = r.get(1)?;
                    let headers_json: String = r.get(2)?;
                    let created_at: i64 = r.get(3)?;
                    let ttl_seconds: i64 = r.get(4)?;
                    Ok((content_hash, status, headers_json, created_at, ttl_seconds))
                },
            )
```

This keeps existing `writer.rs` tests passing — they only store/look up no-Vary entries, all matching the empty-selector row.

- [ ] **Step 8: Run tests, confirm all pass**

```
cargo test -p roxy-cache-fs
```

Expected: all green (migration tests + pre-existing round-trip tests).

- [ ] **Step 9: Commit**

```
git add crates/roxy-cache-fs/src/index.rs crates/roxy-cache-fs/src/writer.rs
git commit -m "refactor(roxy-cache-fs): schema v2 with vary_selector column + drop-on-mismatch migration (roxy-4y6)"
```

---

## Task 4: `Cache` trait gains `req_headers`

API surface change only. Trait grows the parameter; cache implementation and all callers/tests update to pass `&[]` (empty). No behavior change yet.

**Files:**
- Modify: `crates/roxy-cache/src/lib.rs`
- Modify: `crates/roxy-cache-fs/src/writer.rs`
- Modify: `crates/roxy-proxy/src/handler.rs` (callsites at lines ~109 and ~162)

- [ ] **Step 1: Update the trait**

Edit `crates/roxy-cache/src/lib.rs`. Replace the existing `Cache` trait with:

```rust
#[async_trait]
pub trait Cache: Send + Sync {
    async fn lookup(
        &self,
        key: &CacheKey,
        req_headers: &vary::ReqHeaders,
    ) -> Result<Option<CachedResponse>, CacheError>;

    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
        default_ttl: std::time::Duration,
        req_headers: &vary::ReqHeaders,
    ) -> Result<Box<dyn CacheWriter>, CacheError>;
}
```

`vary::ReqHeaders` is already re-exported (Task 2). The fully-qualified path is used here to keep the trait definition unambiguous.

- [ ] **Step 2: Update `FsCache` impl signature**

Edit `crates/roxy-cache-fs/src/writer.rs`. Update both impl method signatures:

```rust
    async fn lookup(
        &self,
        key: &CacheKey,
        _req_headers: &roxy_cache::ReqHeaders,
    ) -> Result<Option<CachedResponse>, CacheError> {
```

```rust
    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
        default_ttl: Duration,
        _req_headers: &roxy_cache::ReqHeaders,
    ) -> Result<Box<dyn CacheWriter>, CacheError> {
```

Bodies remain unchanged for now.

- [ ] **Step 3: Update existing `FsCache` tests**

Find every `cache.lookup(&key).await` and `cache.begin_store(&key, ..., duration).await` call in the `#[cfg(test)] mod tests` of `crates/roxy-cache-fs/src/writer.rs` (four call sites: lines ~253, ~288, ~329, ~342, ~356, ~369 — actual numbers may drift after Task 3). Add `&[]` as the trailing argument to each.

Example, for the `round_trip_store_then_lookup` test:

```rust
        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![("x".to_string(), b"y".to_vec())],
                },
                Duration::from_secs(60),
                &[],
            )
            .await
            .unwrap();
```

```rust
        let hit = cache.lookup(&key, &[]).await.unwrap().unwrap();
```

Apply the same pattern to every other call site in the test module.

- [ ] **Step 4: Update handler call sites**

Edit `crates/roxy-proxy/src/handler.rs`. The two cache calls become:

```rust
            if let Ok(Some(hit)) = self.cache.lookup(&key, &[]).await {
```

```rust
            match self.cache.begin_store(&key, meta, ttl, &[]).await {
```

(Real header plumbing arrives in Task 6.)

- [ ] **Step 5: Run the full workspace build**

```
cargo build --workspace --all-targets
```

Expected: clean build. No new warnings (the unused-prefix `_req_headers` on the impl methods is intentional — clippy will suggest it's unused; the `_` prefix silences that).

- [ ] **Step 6: Run all tests in affected crates**

```
cargo test -p roxy-cache -p roxy-cache-fs -p roxy-proxy --lib
```

Expected: all green.

- [ ] **Step 7: Commit**

```
git add crates/roxy-cache/src/lib.rs crates/roxy-cache-fs/src/writer.rs crates/roxy-proxy/src/handler.rs
git commit -m "refactor(roxy-cache): thread request headers through Cache trait (roxy-4y6)"
```

---

## Task 5: `FsCache` stores + selects by variant

The cache impl now extracts `Vary` from `meta.headers`, computes the selector, and writes both `vary_selector` and `vary_headers`. Lookup queries all rows for `key`, computes the expected selector from `req_headers` against each row's stored `vary_headers`, and returns the first match.

**Files:**
- Modify: `crates/roxy-cache-fs/src/writer.rs`

- [ ] **Step 1: Write the failing tests**

Append to `#[cfg(test)] mod tests` in `crates/roxy-cache-fs/src/writer.rs`:

```rust
    fn req(headers: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect()
    }

    #[tokio::test]
    async fn vary_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);

        let json_req = req(&[("accept", b"application/json")]);
        let html_req = req(&[("accept", b"text/html")]);

        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![("vary".to_string(), b"Accept".to_vec())],
                },
                Duration::from_secs(60),
                &json_req,
            )
            .await
            .unwrap();
        w.write_all(b"json-body").await.unwrap();
        w.finish().await.unwrap();

        // Same variant: hit.
        let hit = cache.lookup(&key, &json_req).await.unwrap();
        assert!(hit.is_some(), "matching variant must hit");
        let body = drain_body(hit.unwrap().body).await;
        assert_eq!(body, b"json-body");

        // Different variant: miss.
        let miss = cache.lookup(&key, &html_req).await.unwrap();
        assert!(miss.is_none(), "different Accept value must miss");
    }

    #[tokio::test]
    async fn two_variants_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);
        let json_req = req(&[("accept", b"application/json")]);
        let html_req = req(&[("accept", b"text/html")]);

        for (req_hdrs, body) in [(&json_req, &b"json-body"[..]), (&html_req, &b"html-body"[..])] {
            let mut w = cache
                .begin_store(
                    &key,
                    ResponseMeta {
                        status: 200,
                        headers: vec![("vary".to_string(), b"Accept".to_vec())],
                    },
                    Duration::from_secs(60),
                    req_hdrs,
                )
                .await
                .unwrap();
            w.write_all(body).await.unwrap();
            w.finish().await.unwrap();
        }

        let json_body = drain_body(cache.lookup(&key, &json_req).await.unwrap().unwrap().body).await;
        let html_body = drain_body(cache.lookup(&key, &html_req).await.unwrap().unwrap().body).await;
        assert_eq!(json_body, b"json-body");
        assert_eq!(html_body, b"html-body");
    }

    #[tokio::test]
    async fn no_vary_and_vary_can_coexist_under_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);

        // No-Vary entry.
        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![],
                },
                Duration::from_secs(60),
                &[],
            )
            .await
            .unwrap();
        w.write_all(b"default-body").await.unwrap();
        w.finish().await.unwrap();

        // Vary entry under the same base key.
        let json_req = req(&[("accept", b"application/json")]);
        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![("vary".to_string(), b"Accept".to_vec())],
                },
                Duration::from_secs(60),
                &json_req,
            )
            .await
            .unwrap();
        w.write_all(b"json-body").await.unwrap();
        w.finish().await.unwrap();

        // Request with no Accept hits the no-Vary entry.
        let default_hit = cache.lookup(&key, &[]).await.unwrap().unwrap();
        assert_eq!(drain_body(default_hit.body).await, b"default-body");

        // Request matching the variant hits the variant.
        let variant_hit = cache.lookup(&key, &json_req).await.unwrap().unwrap();
        assert_eq!(drain_body(variant_hit.body).await, b"json-body");
    }
```

- [ ] **Step 2: Run tests, confirm they fail**

```
cargo test -p roxy-cache-fs --lib writer
```

Expected: `vary_round_trip` and `two_variants_coexist` fail (HTML request mistakenly hits the JSON entry, second variant either collides on PK or never returns from lookup). `no_vary_and_vary_can_coexist_under_same_key` fails for similar reasons.

- [ ] **Step 3: Extract Vary on store**

Edit the body of `FsCache::begin_store` in `crates/roxy-cache-fs/src/writer.rs`. Right before the `Ok(Box::new(FsWriter { … }))` block, compute the selector and stash both fields on the writer. Add two new fields to `FsWriter`:

```rust
pub struct FsWriter {
    tmp_path: PathBuf,
    file: Option<File>,
    hasher: Sha256,
    #[allow(dead_code)]
    bytes_written: u64,
    key: CacheKey,
    meta: ResponseMeta,
    ttl: Duration,
    cache_dir: PathBuf,
    conn: Arc<Mutex<Connection>>,
    vary_selector: Vec<u8>,
    vary_headers: Option<String>,
}
```

In `begin_store`, after the `File::create` and before `Ok(Box::new(...))`:

```rust
        let vary_headers = meta
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("vary"))
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
            .map(|s| s.to_string());
        let vary_selector =
            roxy_cache::compute_selector(vary_headers.as_deref(), req_headers);
```

Then construct `FsWriter` with the two new fields populated:

```rust
        Ok(Box::new(FsWriter {
            tmp_path: tmp,
            file: Some(file),
            hasher: Sha256::new(),
            bytes_written: 0,
            key: key.clone(),
            meta,
            ttl: default_ttl,
            cache_dir: self.cache_dir.clone(),
            conn: self.conn.clone(),
            vary_selector,
            vary_headers,
        }))
```

- [ ] **Step 4: Write selector + Vary into the INSERT**

Replace the `INSERT OR REPLACE` block in `FsWriter::finish` with:

```rust
            conn.execute(
                "INSERT OR REPLACE INTO entries
                   (key, vary_selector, vary_headers, content_hash, status, headers_json, created_at, ttl_seconds)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    self.key.as_bytes(),
                    self.vary_selector.clone(),
                    self.vary_headers.clone(),
                    hash.as_slice(),
                    self.meta.status as i64,
                    headers_json,
                    now,
                    self.ttl.as_secs() as i64,
                ],
            )
```

- [ ] **Step 5: Variant-aware lookup**

Replace the entire body of `FsCache::lookup` (the function defined around line 163) with:

```rust
    async fn lookup(
        &self,
        key: &CacheKey,
        req_headers: &roxy_cache::ReqHeaders,
    ) -> Result<Option<CachedResponse>, CacheError> {
        use futures::StreamExt;
        let candidates: Vec<(Vec<u8>, Option<String>, Vec<u8>, i64, String, i64, i64)> = {
            let conn = self
                .conn
                .lock()
                .map_err(|_| CacheError::Backend("mutex".into()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT vary_selector, vary_headers, content_hash, status, headers_json, created_at, ttl_seconds
                     FROM entries WHERE key = ?1",
                )
                .map_err(|e| CacheError::Backend(e.to_string()))?;
            let rows = stmt
                .query_map([key.as_bytes()], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, i64>(6)?,
                    ))
                })
                .map_err(|e| CacheError::Backend(e.to_string()))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| CacheError::Backend(e.to_string()))?);
            }
            out
        };

        for (vary_selector, vary_headers, content_hash, status, headers_json, created_at, ttl_seconds) in candidates {
            let expected =
                roxy_cache::compute_selector(vary_headers.as_deref(), req_headers);
            if expected != vary_selector {
                continue;
            }
            let hex = hex::encode(&content_hash);
            let path = blob_path(&self.cache_dir, &hex);
            let file = tokio::fs::File::open(&path).await.map_err(CacheError::Io)?;
            let reader = tokio_util::io::ReaderStream::new(file);
            let body: futures::stream::BoxStream<'static, Result<bytes::Bytes, std::io::Error>> =
                reader.boxed();

            let headers: Vec<(String, Vec<u8>)> = serde_json::from_str(&headers_json)
                .map_err(|e| CacheError::Corrupted(e.to_string()))?;

            let created = SystemTime::UNIX_EPOCH + Duration::from_secs(created_at as u64);
            let ttl = Duration::from_secs(ttl_seconds as u64);
            let resp = CachedResponse {
                meta: ResponseMeta {
                    status: status as u16,
                    headers,
                    },
                body,
                created_at: created,
                ttl,
            };
            if resp.is_expired(SystemTime::now()) {
                continue;
            }
            return Ok(Some(resp));
        }
        Ok(None)
    }
```

(Remove any leftover `use futures::StreamExt;` import duplication at the top of the impl.)

- [ ] **Step 6: Run tests, confirm all pass**

```
cargo test -p roxy-cache-fs --lib writer
```

Expected: new Vary tests pass; pre-existing tests (`store_writes_blob_and_indexes`, `abort_discards_tmp`, `round_trip_store_then_lookup`, `ttl_zero_means_immediately_expired`) also pass — they all use empty selectors / no-Vary entries and route through the same lookup loop.

- [ ] **Step 7: Commit**

```
git add crates/roxy-cache-fs/src/writer.rs
git commit -m "feat(roxy-cache-fs): variant-aware lookup keyed by (base, vary_selector) (roxy-4y6)"
```

---

## Task 6: Handler builds and passes request headers

Replace the `&[]` placeholders in `handler.rs` with a real header slice derived from `req.headers()`, gated on `cache_enabled`.

**Files:**
- Modify: `crates/roxy-proxy/src/handler.rs`

- [ ] **Step 1: Build the header slice in `handle_inner`**

Locate `handle_inner` (around line 98). Immediately after the `let key = build_cache_key_and_warn(...)` line (around line 107), add:

```rust
        let req_headers: Vec<(String, Vec<u8>)> = if self.cache_enabled {
            req.headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
                .collect()
        } else {
            Vec::new()
        };
```

- [ ] **Step 2: Pass it to `lookup`**

Replace:

```rust
            if let Ok(Some(hit)) = self.cache.lookup(&key, &[]).await {
```

with:

```rust
            if let Ok(Some(hit)) = self.cache.lookup(&key, &req_headers).await {
```

- [ ] **Step 3: Pass it to `begin_store`**

Replace:

```rust
            match self.cache.begin_store(&key, meta, ttl, &[]).await {
```

with:

```rust
            match self.cache.begin_store(&key, meta, ttl, &req_headers).await {
```

- [ ] **Step 4: Run the proxy crate tests**

```
cargo test -p roxy-proxy --lib
```

Expected: all green. The existing handler-side `label_tests` and similar tests do not exercise caching, so the change is invisible to them.

- [ ] **Step 5: Commit**

```
git add crates/roxy-proxy/src/handler.rs
git commit -m "feat(roxy-proxy): thread request headers into cache lookup/store (roxy-4y6)"
```

---

## Task 7: Integration tests for Vary

End-to-end tests via the fake origin. Adds a `/vary` route to the fixture and a new `cache_vary.rs` test file that drives both the variant-routing happy path and `Vary: *`.

**Files:**
- Modify: `crates/roxy-proxy/tests/common/mod.rs` (add `/vary` route)
- Create: `crates/roxy-proxy/tests/cache_vary.rs`

- [ ] **Step 1: Add the `/vary` route to the fake origin**

Edit `crates/roxy-proxy/tests/common/mod.rs`. After the existing `/cc` route registration (around line 354, before `.route("/echo-headers", ...)`), insert:

```rust
        // `/vary?mode=...` returns a body that echoes the request's Accept
        // header and stamps a Vary response header. `mode=accept` emits
        // `Vary: Accept`; `mode=star` emits `Vary: *`. Hit-counting includes
        // the mode (not the Accept value) so tests can distinguish
        // origin-reach from cache-hit.
        .route(
            "/vary",
            get(
                |State(s): State<OriginState>,
                 Query(q): Query<HashMap<String, String>>,
                 headers: HeaderMap| async move {
                    let mode = q.get("mode").cloned().unwrap_or_default();
                    s.hits.bump(&format!("/vary?mode={mode}"));
                    let accept = headers
                        .get(axum::http::header::ACCEPT)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let mut resp_headers = axum::http::HeaderMap::new();
                    let vary_value = match mode.as_str() {
                        "star" => "*",
                        _ => "Accept",
                    };
                    resp_headers.insert(
                        axum::http::header::VARY,
                        axum::http::HeaderValue::from_static(vary_value),
                    );
                    (resp_headers, format!("body-for-{accept}"))
                },
            ),
        )
```

- [ ] **Step 2: Write the failing integration tests**

Create `crates/roxy-proxy/tests/cache_vary.rs`:

```rust
#![allow(clippy::unwrap_used)]

//! End-to-end tests for response `Vary` handling. Drives the fake origin's
//! `/vary?mode=accept|star` route to make it emit either `Vary: Accept`
//! (variant routing) or `Vary: *` (uncacheable). Asserts that requests with
//! different Vary'd headers do not cross-serve and that `Vary: *` is never
//! stored.

mod common;

use common::{spawn_fixture, FixtureBuilder};

fn build_client(f: &common::Fixture) -> reqwest::Client {
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

fn vary_url(f: &common::Fixture, mode: &str) -> String {
    format!("https://{}/vary?mode={}", f.origin_host, mode)
}

#[tokio::test]
async fn different_accept_get_different_responses() {
    let f = spawn_fixture(3600).await;
    let client = build_client(&f);
    let url = vary_url(&f, "accept");

    let r_json = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(r_json.text().await.unwrap(), "body-for-application/json");
    f.wait_for_n_finalizations(1).await;

    let r_html = client
        .get(&url)
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(r_html.text().await.unwrap(), "body-for-text/html");
    f.wait_for_n_finalizations(2).await;

    assert_eq!(
        f.upstream_hit_count("/vary?mode=accept"),
        2,
        "different Accept values must each reach the origin (no cross-serve)"
    );
}

#[tokio::test]
async fn same_accept_hits_cache() {
    let f = FixtureBuilder::new()
        .default_ttl_seconds(3600)
        .build()
        .await;
    let client = build_client(&f);
    let url = vary_url(&f, "accept");

    let _ = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    f.wait_for_n_finalizations(1).await;

    let r2 = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(r2.text().await.unwrap(), "body-for-application/json");

    assert_eq!(
        f.upstream_hit_count("/vary?mode=accept"),
        1,
        "same Accept value must be served from cache on the second request"
    );
}

#[tokio::test]
async fn vary_star_not_cached() {
    let f = spawn_fixture(3600).await;
    let client = build_client(&f);
    let url = vary_url(&f, "star");

    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();
    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();

    assert_eq!(
        f.upstream_hit_count("/vary?mode=star"),
        2,
        "Vary: * must never be cached"
    );
    assert!(
        f.cache_dir_is_empty(),
        "Vary: *: nothing should be persisted to disk"
    );
}
```

- [ ] **Step 3: Run integration tests, confirm baseline**

```
cargo test -p roxy-proxy --test cache_vary
```

Expected: all three tests pass (Tasks 1–6 have already implemented the behavior). If any fail, debug before continuing — the unit tests in earlier tasks were proxies for end-to-end behavior, and a failure here indicates a missed plumbing point.

- [ ] **Step 4: Run the full test suite as a regression gate**

```
cargo test --workspace
```

Expected: all green. Pay particular attention to `roxy-proxy/tests/cache_control.rs`, `cache_disabled.rs`, `ttl.rs`, and `smoke.rs` — these exercise the same plumbing path and must not regress.

- [ ] **Step 5: Commit**

```
git add crates/roxy-proxy/tests/common/mod.rs crates/roxy-proxy/tests/cache_vary.rs
git commit -m "test(roxy-proxy): end-to-end Vary handling (roxy-4y6)"
```

---

## Task 8: Close beads, push

- [ ] **Step 1: Run clippy + fmt as the workspace gate**

```
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Expected: both succeed with no output. If clippy raises new warnings, fix them inline (most likely candidates: unused imports in `writer.rs` after the lookup rewrite).

- [ ] **Step 2: Close the beads issue**

```
bd close roxy-4y6
```

- [ ] **Step 3: Push**

```
git push
```

---

## Verification matrix (spec → task)

| Spec section | Implemented by |
|---|---|
| Trait signature + `ReqHeaders` alias | Task 2 (alias), Task 4 (signature) |
| `vary.rs` selector algorithm | Task 2 |
| Schema v2 + composite PK | Task 3 |
| Drop-on-mismatch + blob wipe | Task 3 |
| `FsCache::begin_store` writes selector + Vary | Task 5 |
| `FsCache::lookup` variant selection | Task 5 |
| `CacheDirectives.vary_star` | Task 1 |
| Handler plumbs request headers | Task 6 |
| Unit tests (selector) | Task 2 |
| Unit tests (writer round-trip, variants coexist, no-Vary coexist, schema migration) | Tasks 3, 5 |
| Unit tests (cache_directives Vary) | Task 1 |
| Integration tests (different Accept, same Accept, Vary: *) | Task 7 |
| Regression: existing tests still pass | Tasks 4, 5, 6 each verify; Task 7 final gate |
