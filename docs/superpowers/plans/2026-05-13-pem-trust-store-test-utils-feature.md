# PEM Trust-Store `test-utils` Feature Gating Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gate `ImpersonateClient::with_custom_and_extra_root_pem` and the `ROXY_TEST_EXTRA_ROOT_PEM_PATH` env-var read in `serve::build_impersonate` behind a new `test-utils` Cargo feature so neither surface compiles into production binaries, while keeping `cargo test` working without manual feature flags.

**Architecture:** Two crates touched. `roxy-impersonate` gains a `test-utils` feature; the unsafe constructor is gated by `#[cfg(any(test, feature = "test-utils"))]`. `roxy-proxy` gains its own `test-utils` feature that propagates to `roxy-impersonate/test-utils`; the env-var read inside `build_impersonate` is wrapped in the same `cfg` block (no helper function — inline keeps `customs` ownership manageable without forcing `Clone` on `CustomProfile`). A self-dev-dep on `roxy-proxy` activates the feature automatically during `cargo test`.

**Tech Stack:** Rust workspace (cargo 1.95.0), pre-commit hooks via `prek` (rustfmt + clippy).

**Spec:** `docs/superpowers/specs/2026-05-13-pem-trust-store-test-utils-feature-design.md`
**Issues:** `roxy-0vu` (constructor gating), `roxy-qun` (env-var gating). Both are already `in_progress`.

---

## File Structure

- **Modify:** `crates/roxy-impersonate/Cargo.toml`
  - Add `[features]` table with `test-utils = []`.
- **Modify:** `crates/roxy-impersonate/src/client.rs`
  - Add `#[cfg(any(test, feature = "test-utils"))]` attribute above `pub fn with_custom_and_extra_root_pem`.
- **Modify:** `crates/roxy-proxy/Cargo.toml`
  - Add `[features]` table with `test-utils = ["roxy-impersonate/test-utils"]`.
  - Add self-dev-dep entry: `roxy-proxy = { path = ".", features = ["test-utils"] }` under `[dev-dependencies]`.
- **Modify:** `crates/roxy-proxy/src/serve.rs`
  - Refactor `build_impersonate`: extract `verify_default_profile` helper, move the env-var read + unsafe constructor call into an inline `#[cfg(any(test, feature = "test-utils"))]` block, simplify the prod-path conditional.

No new files, no new dependencies (only feature flags on existing deps), no new tests (verification is via release-mode workspace build).

---

## Task 1: Add the `test-utils` feature plumbing

**Files:**
- Modify: `crates/roxy-impersonate/Cargo.toml`
- Modify: `crates/roxy-proxy/Cargo.toml`

This task adds the Cargo machinery (features + self-dev-dep) without gating any code yet. The workspace continues to build and test exactly as before; this is purely scaffolding. Keeping it separate from the code gating lets us verify the self-dev-dep idiom works in isolation.

- [ ] **Step 1: Edit `crates/roxy-impersonate/Cargo.toml`**

After the `[lints]` block and before `[dependencies]`, insert:

```toml
[features]
test-utils = []
```

So the top of the file becomes:

```toml
[package]
name = "roxy-impersonate"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[features]
test-utils = []

[dependencies]
...
```

- [ ] **Step 2: Edit `crates/roxy-proxy/Cargo.toml`**

After the `[lints]` block and before `[dependencies]`, insert:

```toml
[features]
test-utils = ["roxy-impersonate/test-utils"]
```

And at the very end of the `[dev-dependencies]` block (after the existing `serde_json` line), add the self-dev-dep:

```toml
roxy-proxy = { path = ".", features = ["test-utils"] }
```

So the relevant portion becomes:

```toml
[lints]
workspace = true

[features]
test-utils = ["roxy-impersonate/test-utils"]

[dependencies]
...

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
axum = { version = "0.7", features = ["http2"] }
axum-server = { version = "0.7", features = ["tls-rustls"] }
tempfile = "3.13"
rustls = { workspace = true }
rustls-pki-types = { workspace = true }
rcgen = { workspace = true }
roxy-config = { workspace = true }
tracing-subscriber = { workspace = true }
serde_json = { workspace = true }
roxy-proxy = { path = ".", features = ["test-utils"] }
```

- [ ] **Step 3: Verify the workspace still builds (no `test-utils`)**

Run: `cargo build --workspace`
Expected: clean build (no errors).

- [ ] **Step 4: Verify release build still works (no `test-utils`)**

Run: `cargo build --release --workspace`
Expected: clean build.

- [ ] **Step 5: Verify the self-dev-dep activates `test-utils` during `cargo test`**

Run: `cargo test --workspace`
Expected: clean build of all targets, all existing tests pass.

If this step fails with a cargo error about self-references (e.g., "cyclic package dependency" or similar), the self-dev-dep idiom is not working in this configuration. Fallback:
  1. Remove the `roxy-proxy = { path = ".", features = ["test-utils"] }` line from `[dev-dependencies]`.
  2. Update the commit message and the AGENTS.md / README to document that tests now require `cargo test --workspace --features test-utils -p roxy-proxy`.
  3. Re-run `cargo test --workspace --features test-utils -p roxy-proxy` to confirm tests pass.
  4. Note the fallback in the commit message: "self-dev-dep didn't resolve cleanly; tests must pass `--features test-utils` explicitly."

For now, proceed assuming the self-dev-dep works — it is a standard cargo idiom on 1.95.

- [ ] **Step 6: Confirm the feature tables are well-formed**

Run: `cargo metadata --format-version=1 --no-deps 2>/dev/null | python3 -c "
import json, sys
m = json.load(sys.stdin)
for name in ('roxy-impersonate', 'roxy-proxy'):
    pkg = [p for p in m['packages'] if p['name'] == name][0]
    feats = pkg.get('features', {})
    assert 'test-utils' in feats, f'{name} is missing test-utils feature: {feats}'
    print(f'{name}.features = {feats}')
"`

Expected: both `roxy-impersonate.features` and `roxy-proxy.features` print, each containing a `test-utils` key. No `AssertionError` raised.

This confirms the feature tables parsed correctly. Actual activation during tests is verified end-to-end in the next step.

- [ ] **Step 7: Run clippy**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 8: Run rustfmt**

Run: `cargo fmt --all`
Expected: no output (or trivial changes).

- [ ] **Step 9: Commit**

```bash
git add crates/roxy-impersonate/Cargo.toml crates/roxy-proxy/Cargo.toml
git commit -m "$(cat <<'EOF'
chore(roxy-impersonate,roxy-proxy): add test-utils feature scaffolding

Adds [features] tables and a self-dev-dep on roxy-proxy so the test-utils
feature activates automatically during cargo test but stays off in
production builds. No code is gated yet — this commit just establishes
the cargo machinery. Follow-up commit gates the unsafe surfaces.

Part of roxy-0vu and roxy-qun.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Gate the unsafe surfaces

**Files:**
- Modify: `crates/roxy-impersonate/src/client.rs`
- Modify: `crates/roxy-proxy/src/serve.rs`

Atomic change: gate the constructor AND the env-var read together in one commit. If you gate just the constructor without the callsite, the workspace fails to build without `--features test-utils`.

- [ ] **Step 1: Gate the constructor in `client.rs`**

In `crates/roxy-impersonate/src/client.rs`, locate the `with_custom_and_extra_root_pem` method (currently at lines ~57-84, starting with the rustdoc comment `/// Like [Self::with_custom]...`). Add a `#[cfg(any(test, feature = "test-utils"))]` attribute immediately above the `pub fn` line (after the rustdoc).

Concretely, change:

```rust
    /// Like [`Self::with_custom`] but installs an explicit TLS trust store
    /// from the supplied PEM-encoded root certificate(s). The supplied store
    /// REPLACES wreq's default trust (webpki-roots), so callers must include
    /// every CA they need to verify upstream peers.
    ///
    /// Intended primarily for integration tests that need to talk to a fake
    /// origin signed by a private CA — wreq's `webpki-roots` default trust
    /// store does not consult `SSL_CERT_FILE`, so test code must supply the
    /// test CA explicitly. Production callers wanting "webpki + extras"
    /// must concatenate the public root PEMs with their internal root PEM
    /// in `extra_root_pem`.
    pub fn with_custom_and_extra_root_pem(
```

To:

```rust
    /// Like [`Self::with_custom`] but installs an explicit TLS trust store
    /// from the supplied PEM-encoded root certificate(s). The supplied store
    /// REPLACES wreq's default trust (webpki-roots), so callers must include
    /// every CA they need to verify upstream peers.
    ///
    /// Intended primarily for integration tests that need to talk to a fake
    /// origin signed by a private CA — wreq's `webpki-roots` default trust
    /// store does not consult `SSL_CERT_FILE`, so test code must supply the
    /// test CA explicitly. Production callers wanting "webpki + extras"
    /// must concatenate the public root PEMs with their internal root PEM
    /// in `extra_root_pem`.
    ///
    /// Gated behind the `test-utils` Cargo feature (and `cfg(test)` for
    /// internal unit tests) so this footgun is not present in production
    /// binaries. Production callers should never need this constructor.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_custom_and_extra_root_pem(
```

Only the rustdoc tail and the `#[cfg(...)]` line are new. The function body is unchanged.

- [ ] **Step 2: Verify the workspace still builds at this intermediate state**

Run: `cargo build --workspace`

Expected: this will FAIL because `serve.rs` still references `with_custom_and_extra_root_pem` unconditionally, and the symbol is now gated. Error will look like:
```
error[E0599]: no function or associated item named `with_custom_and_extra_root_pem` found for struct `ImpersonateClient`
```

This failure is expected at this intermediate state. Do not commit here. Proceed to Step 3 which fixes serve.rs.

- [ ] **Step 3: Refactor `serve::build_impersonate` in `crates/roxy-proxy/src/serve.rs`**

Locate the current `build_impersonate` function (lines ~80-114). Replace the entire function body with the inline-cfg refactor, and add a new `verify_default_profile` helper immediately after it. Concretely, the new code for these two functions is:

```rust
fn build_impersonate(cfg: &Config) -> anyhow::Result<Option<roxy_impersonate::ImpersonateClient>> {
    let customs = roxy_impersonate::CustomProfile::load_dir(&cfg.impersonate.profiles_dir)
        .context("load custom profiles")?;

    // Test-only: ROXY_TEST_EXTRA_ROOT_PEM_PATH lets the integration test
    // fixture inject a private CA so the impersonate client trusts the
    // test fixture's fake origin. Both the env-var read and the unsafe
    // constructor it calls are gated behind the `test-utils` feature so
    // production builds cannot be tricked into swapping their trust
    // store via a stray env var.
    #[cfg(any(test, feature = "test-utils"))]
    {
        if let Some(pem_path) = std::env::var("ROXY_TEST_EXTRA_ROOT_PEM_PATH")
            .ok()
            .filter(|s| !s.is_empty())
        {
            let pem = std::fs::read(&pem_path)
                .with_context(|| format!("ROXY_TEST_EXTRA_ROOT_PEM_PATH={pem_path}"))?;
            let client = roxy_impersonate::ImpersonateClient::with_custom_and_extra_root_pem(
                customs, &pem,
            )
            .context("impersonate client with extra root PEM")?;
            return Ok(Some(verify_default_profile(client, cfg)?));
        }
    }

    if cfg.impersonate.default_profile.is_none() && customs.is_empty() {
        return Ok(None);
    }
    let client = roxy_impersonate::ImpersonateClient::with_custom(customs);
    Ok(Some(verify_default_profile(client, cfg)?))
}

fn verify_default_profile(
    client: roxy_impersonate::ImpersonateClient,
    cfg: &Config,
) -> anyhow::Result<roxy_impersonate::ImpersonateClient> {
    if let Some(name) = &cfg.impersonate.default_profile {
        if !client.has_profile(name) {
            let avail = client.profile_names().join(", ");
            anyhow::bail!("unknown default profile {name:?}; available: [{avail}]");
        }
    }
    Ok(client)
}
```

The existing rustdoc comment above `build_impersonate` (the paragraph starting with `/// Construct the optional ImpersonateClient based on config.`) stays unchanged. Only the function body is replaced, and `verify_default_profile` is added below.

If linting prefers single-statement `if let` over `{ if let ... { ... } }`, the inner braces can be flattened, but the outer `#[cfg(...)] { ... }` block is required because `#[cfg]` cannot be applied to a bare `if`.

- [ ] **Step 4: Verify the production-mode workspace builds**

Run: `cargo build --release --workspace`
Expected: clean build. This is the load-bearing verification step — release build does NOT include dev-dependencies, so `test-utils` is OFF, so the gated surfaces are absent from the binary. Success here means the unsafe constructor and env-var read are unreachable in production.

- [ ] **Step 5: Verify the test build works**

Run: `cargo test --workspace`
Expected: clean build of all targets, all existing tests pass (integration tests in `crates/roxy-proxy/tests/` continue to exercise the env-var path through the test fixture in `tests/common/mod.rs:295`).

- [ ] **Step 6: Verify clippy on the production view (lib/bin only)**

Run: `cargo clippy --workspace -- -D warnings`
Expected: clean. This view has `test-utils` off and the gated code is absent; clippy validates the production code paths.

- [ ] **Step 7: Verify clippy on the test view (all targets)**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean. This view has dev-deps active and `test-utils` on; clippy validates the gated code paths too.

If either Step 6 or Step 7 produces a `dead_code` or `unused_imports` warning on something that became dead in one view but not the other, address it by either: (a) adding `#[cfg(any(test, feature = "test-utils"))]` to the dead item, or (b) reorganizing so the import is only present in the active view. Do not use `#[allow(dead_code)]` as a workaround.

- [ ] **Step 8: Run rustfmt**

Run: `cargo fmt --all`
Expected: no output or trivial changes.

- [ ] **Step 9: Commit**

```bash
git add crates/roxy-impersonate/src/client.rs crates/roxy-proxy/src/serve.rs
git commit -m "$(cat <<'EOF'
fix(roxy-impersonate,roxy-proxy): gate PEM trust-store footgun behind test-utils

Production binaries can no longer compile:
  - ImpersonateClient::with_custom_and_extra_root_pem (silently replaces
    wreq's default trust store with the supplied PEM)
  - the ROXY_TEST_EXTRA_ROOT_PEM_PATH env-var read in serve::build_impersonate

Both surfaces are now gated by #[cfg(any(test, feature = "test-utils"))].
The test-utils feature is activated automatically during cargo test via
the self-dev-dep added in the prior commit, so integration tests work
without manual --features flags. cargo build --release --workspace
proves the gated surfaces are absent from production builds.

Closes roxy-0vu and roxy-qun.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Close beads issues and push

- [ ] **Step 1: Close both beads issues in one command**

Run: `bd close roxy-0vu roxy-qun --reason="Gated behind test-utils Cargo feature; production builds no longer compile the unsafe constructor or the env-var read. Verified by cargo build --release --workspace."`
Expected: `✓ Closed issue: roxy-0vu` and `✓ Closed issue: roxy-qun`.

- [ ] **Step 2: Push to remote**

Run: `git push`
Expected: push succeeds, fast-forwards `main` to include the two new commits.

- [ ] **Step 3: Confirm clean state**

Run: `git status && bd ready | head -3`
Expected: working tree clean (modulo untracked `.claude/` and `target/`); `bd ready` no longer lists `roxy-0vu` or `roxy-qun`.

---

## Verification Summary

After all three tasks complete:

- `grep -rn "with_custom_and_extra_root_pem" crates/ --include="*.rs"` → matches only inside `#[cfg(...)]` blocks (production callers all gated).
- `cargo build --release --workspace` → clean (proves gated surfaces absent from prod binary).
- `cargo test --workspace` → all pass (proves test-utils auto-activates).
- `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- `cargo clippy --workspace -- -D warnings` → clean (prod view).
- `bd show roxy-0vu` and `bd show roxy-qun` → status `closed`.
- A future production engineer who tries to call `ImpersonateClient::with_custom_and_extra_root_pem` from non-test code gets a compile error pointing at the missing symbol.
- A misconfigured prod environment that sets `ROXY_TEST_EXTRA_ROOT_PEM_PATH` is silently ignored — the env var is no longer read.
