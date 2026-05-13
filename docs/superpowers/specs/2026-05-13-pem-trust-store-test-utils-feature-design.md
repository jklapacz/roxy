# Gate PEM-trust-store footgun behind `test-utils` feature

**Issues:** roxy-0vu, roxy-qun
**Date:** 2026-05-13
**Status:** Design approved, awaiting plan

## Problem

Two related P2 security footguns share the same root cause: production code can
silently replace `wreq`'s default TLS trust store (webpki-roots) with an
arbitrary PEM, breaking certificate verification for every public origin.

1. **`ImpersonateClient::with_custom_and_extra_root_pem`**
   (`crates/roxy-impersonate/src/client.rs:68`) is unconditionally `pub`.
   Production callers reaching for an "augment trust" feature will use it and
   *replace* the trust store with whatever PEM they pass — not add to it.
2. **`serve::build_impersonate`** (`crates/roxy-proxy/src/serve.rs:92-102`)
   unconditionally reads the env var `ROXY_TEST_EXTRA_ROOT_PEM_PATH` and, if
   set, passes the file's contents to the unsafe constructor above. A
   misconfigured or hostile prod environment that sets this env var swaps the
   binary's trust store at startup with no warning.

Neither surface has any production caller. Verified by grep: both are exercised
only by integration tests (`crates/roxy-proxy/tests/common/mod.rs:295`).

## Goals

1. The unsafe constructor is not present in production binaries.
2. The env-var read is not present in production binaries.
3. Integration tests continue to work via `cargo test` without manual feature
   flags or special invocations.
4. The change establishes a clean `[features]` convention for the workspace
   (none exists today).

## Non-goals

- Not changing the replace-vs-augment semantics of
  `with_custom_and_extra_root_pem`. Leaving as-is — only test code uses it,
  and tests need exactly this behavior (the test fixture's fake origin is
  signed by a CA that the default trust store doesn't know).
- Not renaming `ROXY_TEST_EXTRA_ROOT_PEM_PATH`. The name already says "TEST";
  the gating is what matters.
- Not removing the `cert_store: Option<wreq::tls::CertStore>` field from
  `ImpersonateClient`. It stays (always `None` in prod builds) so that
  `client_for` doesn't need cfg gating.

## Design

Two crates touched: `roxy-impersonate` and `roxy-proxy`. Both gain a
`test-utils` Cargo feature. The unsafe surfaces are gated by
`#[cfg(any(test, feature = "test-utils"))]`. Production builds compile without
the feature; tests turn it on automatically via the self-dev-dep idiom.

### Change 1 — `roxy-impersonate`

`crates/roxy-impersonate/Cargo.toml`:

```toml
[features]
test-utils = []
```

`crates/roxy-impersonate/src/client.rs`: gate the constructor.

```rust
#[cfg(any(test, feature = "test-utils"))]
pub fn with_custom_and_extra_root_pem(
    customs: Vec<CustomProfile>,
    extra_root_pem: &[u8],
) -> Result<Self, ImpersonateError> {
    // body unchanged
}
```

The `cert_store` field on `ImpersonateClient` stays in place across all build
configurations. `client_for`'s `if let Some(store) = &self.cert_store` branch
stays — it's just always-false in prod. This avoids cfg-fragmentation across
the struct.

Internal unit tests in `roxy-impersonate` (the `#[cfg(test)] mod tests` block
at the bottom of `client.rs`) continue to work because `cfg(test)` is part of
the gate. Today those tests don't reference the gated constructor, but the
`cfg(any(test, …))` form is belt-and-suspenders for future internal tests.

### Change 2 — `roxy-proxy`

`crates/roxy-proxy/Cargo.toml`:

```toml
[features]
test-utils = ["roxy-impersonate/test-utils"]
```

Add the self-dev-dep for automatic activation during `cargo test`:

```toml
[dev-dependencies]
roxy-proxy = { path = ".", features = ["test-utils"] }
# existing dev-dependencies unchanged
```

This is the canonical pattern for "feature should be on for `cargo test` but
off for `cargo build`": cargo brings in `[dev-dependencies]` only during test
builds, and feature unification activates `test-utils` whenever the self-dep
is pulled in.

`crates/roxy-proxy/src/serve.rs`: refactor `build_impersonate` to isolate the
test-only code path in an inline cfg-gated block. Inline (rather than helper
function) so that `customs` can be moved by value into the gated branch
without requiring `CustomProfile: Clone` — the type is not `Clone` today and
deriving it would force `wreq::Emulation: Clone` etc., out of scope here.

```rust
fn build_impersonate(cfg: &Config) -> anyhow::Result<Option<roxy_impersonate::ImpersonateClient>> {
    let customs = roxy_impersonate::CustomProfile::load_dir(&cfg.impersonate.profiles_dir)
        .context("load custom profiles")?;

    // Test-only: ROXY_TEST_EXTRA_ROOT_PEM_PATH lets the integration test
    // fixture inject a private CA. The env-var read and the unsafe
    // constructor it calls are both gated behind `test-utils`.
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

Key properties of this refactor:

- The `std::env::var("ROXY_TEST_EXTRA_ROOT_PEM_PATH")` call appears nowhere
  in prod builds — it's inside a `#[cfg(any(test, feature = "test-utils"))]`
  block.
- The reference to `with_custom_and_extra_root_pem` is inside the gated
  block, so prod builds don't reference a symbol that's also cfg'd out.
- `customs` is moved by value into the test-path branch when entered;
  otherwise it falls through to the prod path which moves it into
  `with_custom`. The borrow checker handles the conditional move because
  the test-path branch always early-returns.
- `verify_default_profile` is shared by both paths; no duplicated logic.

## Verification

The implementation plan will include one explicit verification step:

```
cargo build --release --workspace
```

This must succeed without `--features test-utils`. Successful release build
proves both gated surfaces are absent from the compiled binary.

`cargo test --workspace` activates `test-utils` automatically via the
self-dev-dep and must continue to pass (all existing integration tests in
`crates/roxy-proxy/tests/` use the env var indirectly through the test fixture).

No `compile_fail` doctests, no symbol-grepping in binaries — the cfg attribute
is doing the work; the release-build success is sufficient evidence.

## Risk / migration notes

- **Self-dev-dep idiom.** Known pattern, used in many Rust projects, but the
  workspace doesn't use it yet. If cargo refuses to resolve the self-dep in
  this specific setup, the fallback is two-fold: (a) document
  `cargo test --workspace --features test-utils` in `AGENTS.md`, and (b) add
  the feature activation to any CI script. Verify during implementation that
  the self-dev-dep approach actually works before relying on it.

- **Pre-commit clippy.** Pre-commit runs `cargo clippy` on staged files
  without specifying features, so it sees the prod build's view (no
  `test-utils`). The cfg-gated code blocks are absent from clippy's view in
  that mode. Both views (with and without `test-utils`) must independently be
  warning-free; the implementation plan will verify both.

- **Workspace-wide test invocations.** `cargo test --workspace` will work as
  before: each crate's dev-deps activate during its own test build, and the
  self-dev-dep on `roxy-proxy` ensures `test-utils` is on whenever that crate
  is being tested. Other crates that don't depend on `roxy-impersonate` are
  unaffected.

## Out of this design

- Restructuring `wreq` integration to support augmenting webpki-roots with
  extra PEMs (the "approach B" alternative from brainstorming). Deferred as a
  separate piece of work if/when a real production "extra trust" requirement
  appears.
- Moving test helpers into a dedicated `roxy-impersonate-testing` crate
  (the "approach C" alternative). Deferred; not justified for two functions.
- Removing `ROXY_TEST_EXTRA_ROOT_PEM_PATH` as the mechanism in favor of a
  function parameter that integration tests pass explicitly. Possible future
  cleanup but out of scope here — the env var mechanism is already established
  in the test fixture and works.
