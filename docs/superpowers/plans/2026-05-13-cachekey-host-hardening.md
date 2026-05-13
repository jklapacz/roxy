# CacheKey Host-Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the cross-origin cache-poisoning vector in `CacheKey::from_request` by always keying cache entries against the CONNECT authority, warning on client Host mismatch, and removing the unsafe API.

**Architecture:** Two-crate change. (1) `roxy-proxy/src/handler.rs` gains three private free functions — `client_authority`, `authority_matches`, `build_cache_key_and_warn` — plus a test-only `captured_warnings` utility. `Handler::handle` is migrated to call the new helper instead of `CacheKey::from_request`. (2) `roxy-cache/src/key.rs` then deletes `from_request` and its now-stale unit test. The cache crate's keying module stops knowing about `http::Request`.

**Tech Stack:** Rust workspace, `http` crate, `tracing` + `tracing-subscriber` (already workspace deps), `cargo` + `pre-commit` (rustfmt + clippy).

**Spec:** `docs/superpowers/specs/2026-05-13-cachekey-host-hardening-design.md`
**Issue:** `roxy-4gj` (already `in_progress`)

---

## File Structure

- **Modify:** `crates/roxy-proxy/src/handler.rs`
  - Add three private free functions: `client_authority`, `authority_matches`, `build_cache_key_and_warn`.
  - Replace direct `CacheKey::from_request` call in `Handler::handle` (line 59) with `build_cache_key_and_warn`.
  - Add a `#[cfg(test)] mod key_tests` with a `captured_warnings` helper and three behavioral tests.

- **Modify:** `crates/roxy-cache/src/key.rs`
  - Delete `pub fn from_request<B>(…)` method (lines 45-65).
  - Delete `from_request_picks_authority_from_uri` test (lines 112-121).
  - Remove the now-unused `use http::Request;` import if no other code in `key.rs` references it.

No new crates, no new dependencies. `tracing-subscriber` is already in `crates/roxy-proxy/Cargo.toml` as both a normal and dev dependency.

---

## Task 1: Add helpers, migrate callsite, add tests

**Files:**
- Modify: `crates/roxy-proxy/src/handler.rs`

This is one atomic task because (a) the new helper exists alongside the still-imported `CacheKey::from_request` in this commit, then the callsite swap happens before commit, and (b) the test module exercises the helper directly so there is no "dead code" window. After this task the workspace still builds (`from_request` is still defined in `roxy-cache` but no longer called).

- [ ] **Step 1: Read the current handler.rs to confirm the import block and test module location**

Run: `cat crates/roxy-proxy/src/handler.rs | head -10`
Expected: top imports include `use roxy_cache::{Cache, CacheKey, CacheWriter};`

- [ ] **Step 2: Add the `captured_warnings` test utility inside the existing `#[cfg(test)] mod label_tests` block? No — add a fresh `#[cfg(test)] mod key_tests` module at the bottom of the file, after `label_tests`**

Append this block to the end of `crates/roxy-proxy/src/handler.rs`:

```rust
#[cfg(test)]
mod key_tests {
    use super::*;
    use http::Request;
    use roxy_cache::CacheKey;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured_warnings(f: impl FnOnce()) -> String {
        let writer = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(writer.0.lock().unwrap().clone()).unwrap()
    }
}
```

- [ ] **Step 3: Verify the file still compiles before adding any failing tests**

Run: `cargo build -p roxy-proxy --tests`
Expected: clean build (no errors, no warnings about unused `CaptureWriter` etc. — the struct is used inside the helper).

- [ ] **Step 4: Add the first failing test inside `mod key_tests`**

Append inside `mod key_tests { … }`, after `captured_warnings`:

```rust
    #[test]
    fn cache_key_uses_connect_authority() {
        let req = Request::get("/api")
            .header(http::header::HOST, "attacker.com")
            .body(())
            .unwrap();
        let key = build_cache_key_and_warn(&req, "p", "bank.com:443");
        let expected = CacheKey::from_parts("p", "GET", "https", "bank.com:443", "/api", None);
        assert_eq!(key, expected);
    }
```

- [ ] **Step 5: Run the test to verify it fails to compile**

Run: `cargo test -p roxy-proxy --lib key_tests::cache_key_uses_connect_authority`
Expected: FAIL at compile — `cannot find function 'build_cache_key_and_warn' in this scope` (or similar).

- [ ] **Step 6: Add the three helper functions to `handler.rs`**

Insert these three free functions in `handler.rs` immediately after the `resolve_label` function (just before `fn upstream_kind`):

```rust
fn client_authority<B>(req: &Request<B>) -> Option<String> {
    if let Some(h) = req.uri().host() {
        return Some(h.to_string());
    }
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn authority_matches(connect: &str, client: &str) -> bool {
    fn normalize(s: &str) -> String {
        let lower = s.to_ascii_lowercase();
        lower
            .strip_suffix(":443")
            .map(|s| s.to_string())
            .unwrap_or(lower)
    }
    normalize(connect) == normalize(client)
}

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

    if let Some(client_host) = client_authority(req) {
        if !authority_matches(authority, &client_host) {
            tracing::warn!(
                connect_authority = %authority,
                client_host = %client_host,
                kind = "host_mismatch",
                "client Host/URI authority disagrees with CONNECT authority; \
                 keying by CONNECT authority"
            );
        }
    }
    key
}
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cargo test -p roxy-proxy --lib key_tests::cache_key_uses_connect_authority`
Expected: PASS (`test result: ok. 1 passed`).

- [ ] **Step 8: Add the second failing test**

Append inside `mod key_tests`, after `cache_key_uses_connect_authority`:

```rust
    #[test]
    fn host_mismatch_emits_warning() {
        let req = Request::get("/api")
            .header(http::header::HOST, "attacker.com")
            .body(())
            .unwrap();
        let output = captured_warnings(|| {
            let _ = build_cache_key_and_warn(&req, "p", "bank.com:443");
        });
        assert!(
            output.contains("kind=\"host_mismatch\""),
            "expected host_mismatch warning, got: {output}"
        );
        assert!(
            output.contains("connect_authority=\"bank.com:443\""),
            "expected connect_authority in warning, got: {output}"
        );
        assert!(
            output.contains("client_host=\"attacker.com\""),
            "expected client_host in warning, got: {output}"
        );
    }
```

- [ ] **Step 9: Run the test to verify it passes**

Run: `cargo test -p roxy-proxy --lib key_tests::host_mismatch_emits_warning`
Expected: PASS.

If the assertion fails because `tracing-subscriber`'s formatter quotes field values differently than expected, inspect the actual output (visible in the test failure message) and adjust the substring assertions to match the real format. Do NOT change the production warning fields — only adapt the test's substring matching.

- [ ] **Step 10: Add the third failing test**

Append inside `mod key_tests`, after `host_mismatch_emits_warning`:

```rust
    #[test]
    fn matching_host_does_not_warn() {
        let req = Request::get("/api")
            .header(http::header::HOST, "bank.com")
            .body(())
            .unwrap();
        let output = captured_warnings(|| {
            let _ = build_cache_key_and_warn(&req, "p", "bank.com:443");
        });
        assert!(
            !output.contains("host_mismatch"),
            "expected no warning for matching host (default port stripped), got: {output}"
        );
    }
```

- [ ] **Step 11: Run the test to verify it passes**

Run: `cargo test -p roxy-proxy --lib key_tests::matching_host_does_not_warn`
Expected: PASS.

- [ ] **Step 12: Migrate the production callsite in `Handler::handle`**

In `crates/roxy-proxy/src/handler.rs`, replace this single line:

```rust
        let key = CacheKey::from_request(&req, &label, "https", &authority);
```

with:

```rust
        let key = build_cache_key_and_warn(&req, &label, &authority);
```

(The `"https"` literal moves into `build_cache_key_and_warn` itself — no scheme parameter needed because the handler is only invoked from inside a CONNECT-tunneled TLS session.)

- [ ] **Step 13: Run the full roxy-proxy test suite**

Run: `cargo test -p roxy-proxy`
Expected: all tests pass, including the existing integration tests in `tests/impersonate.rs` and the new `key_tests`.

- [ ] **Step 14: Run clippy on the modified crate**

Run: `cargo clippy -p roxy-proxy --all-targets -- -D warnings`
Expected: clean, no warnings.

- [ ] **Step 15: Run rustfmt**

Run: `cargo fmt -p roxy-proxy`
Expected: no output (no changes needed) or minor formatting fixes.

- [ ] **Step 16: Commit**

```bash
git add crates/roxy-proxy/src/handler.rs
git commit -m "$(cat <<'EOF'
feat(roxy-proxy): key cache by CONNECT authority + warn on Host mismatch

Add build_cache_key_and_warn helper in handler.rs that derives the cache
key from the CONNECT authority (the only trustworthy host identity inside
a MITM tunnel) and emits a structured warning when the client's Host
header / URI authority disagrees with it.

Removes the cross-origin cache-poisoning vector reachable when a client
sent Host: attacker.com over a CONNECT to bank.com.

Part of roxy-4gj. Follow-up commit removes CacheKey::from_request.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Remove `CacheKey::from_request`

**Files:**
- Modify: `crates/roxy-cache/src/key.rs`

The unsafe API has no remaining callers (verified at design time; Task 1 removed the last one). This task deletes the function and its now-incorrect unit test.

- [ ] **Step 1: Delete the `from_request` method**

In `crates/roxy-cache/src/key.rs`, remove lines 45-65 (the entire `pub fn from_request<B>(…) -> Self { … }` block).

- [ ] **Step 2: Delete the now-stale unit test**

In the same file, remove the `from_request_picks_authority_from_uri` test (lines 112-121 in the pre-edit file). It tested behavior that is no longer correct (URI host should not influence the cache key).

- [ ] **Step 3: Remove the now-unused `http::Request` import if no other code in the file uses it**

Check whether `use http::Request;` at the top of `crates/roxy-cache/src/key.rs` is still referenced. If not, delete that line.

Run: `grep -n "Request" crates/roxy-cache/src/key.rs`
Expected: no matches outside the import line. If so, delete the import.

- [ ] **Step 4: Build the cache crate**

Run: `cargo build -p roxy-cache`
Expected: clean build.

- [ ] **Step 5: Run the cache-crate tests**

Run: `cargo test -p roxy-cache`
Expected: all remaining tests pass; one fewer test than before.

- [ ] **Step 6: Build the full workspace to confirm nothing else depended on `from_request`**

Run: `cargo build --workspace --all-targets`
Expected: clean build. (If anything fails here, a caller was missed during design — grep again and migrate it.)

- [ ] **Step 7: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: all tests pass.

- [ ] **Step 8: Clippy on the workspace**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 9: rustfmt**

Run: `cargo fmt --all`
Expected: no output or minor fixes.

- [ ] **Step 10: Commit**

```bash
git add crates/roxy-cache/src/key.rs
git commit -m "$(cat <<'EOF'
refactor(roxy-cache): remove CacheKey::from_request

The function silently fell back through URI host → Host header →
default_host, letting client-controlled headers win over the trusted
CONNECT authority. Callers have been migrated to from_parts with
explicit, trusted inputs (see prior commit). Removing the API so it
can't be reintroduced.

Closes roxy-4gj.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Close beads issue and push

- [ ] **Step 1: Close the beads issue**

Run: `bd close roxy-4gj --reason="Cache key now derives from CONNECT authority; from_request removed. See commits."`
Expected: `✓ Closed issue: roxy-4gj`.

- [ ] **Step 2: Push to remote** (per SESSION CLOSE PROTOCOL in CLAUDE config)

Run: `git push`
Expected: push succeeds, fast-forwards `main` to include the two new commits.

- [ ] **Step 3: Confirm clean state**

Run: `git status && bd ready`
Expected: working tree clean, `bd ready` no longer lists `roxy-4gj`.

---

## Verification Summary

After all three tasks, the following should hold:

- `grep -rn "CacheKey::from_request" crates/` → no results.
- `cargo test --workspace` → all pass.
- `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- `bd show roxy-4gj` → status `closed`.
- A request sent through the proxy with `CONNECT bank.com:443` + inner `Host: attacker.com` is cached under a key naming `bank.com:443` (not `attacker.com`), and a `host_mismatch`-kinded warning is emitted in the proxy logs.
