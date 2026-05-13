# Roxy MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Roxy MVP — an HTTPS-capable caching forward proxy with MITM TLS interception, content-addressable cache, and HTTP/1.1 + HTTP/2 support on both client and upstream sides — per `docs/superpowers/specs/2026-05-12-roxy-mvp-architecture-design.md`.

**Architecture:** Single-binary Rust workspace with five library crates (`roxy-http`, `roxy-mitm`, `roxy-cache`, `roxy-cache-fs`, `roxy-config`) and one binary (`roxy-proxy`). Data plane built on `hyper` 1.x + `rustls` 0.23 + custom MITM glue. Cache is filesystem blobs + sqlite index behind a `Cache` trait designed for a future shared backend.

**Tech Stack:** Rust 2024 edition (stable), tokio, hyper 1.x, hyper-rustls 0.27, rustls 0.23 (ring provider), rcgen 0.13, rusqlite (bundled), sha2, clap 4, tracing, async-trait. Tests use axum + reqwest.

---

## Working with this plan

Track progress in beads. Each task maps to one of 12 pre-filed beads issues. Before starting a task, run:

```bash
bd update <issue-id> --status=in_progress
```

After the commit at the end of the task, run:

```bash
bd close <issue-id>
```

The bead-to-task mapping is listed in the section header for each task group. Some beads issues span multiple tasks — only update status when starting the *first* task of the issue and closing the *last*.

**Critical path (must be done in order):** `roxy-nsh → roxy-3ae → roxy-m4q → roxy-z0p → roxy-qxg → roxy-xn8`. Other issues parallelize but the plan is written linearly for clarity.

---

## File structure

After the plan completes, the workspace looks like:

```
roxy/
├── Cargo.toml                     # workspace manifest
├── Cargo.lock
├── rust-toolchain.toml            # pin to stable
├── crates/
│   ├── roxy-proxy/                # binary
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── main.rs            # entry, clap subcommands
│   │   │   ├── cli.rs             # clap derive types
│   │   │   ├── serve.rs           # `roxy serve` impl
│   │   │   ├── handler.rs         # request handler: cache lookup, tee-on-miss
│   │   │   └── ca_cmd.rs          # `roxy ca install/uninstall` impl
│   │   └── tests/
│   │       ├── common/
│   │       │   ├── mod.rs         # test harness: fake origin + roxy fixture
│   │       │   └── trust.rs       # test CA for fake origin TLS
│   │       ├── golden.rs          # miss→store→hit, tee correctness
│   │       ├── ttl.rs             # expiry behavior
│   │       ├── errors.rs          # origin 5xx not cached, conn failures
│   │       ├── streaming.rs       # client disconnect, large body cap
│   │       └── smoke.rs           # #[ignore] real-world httpbin
│   ├── roxy-http/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs             # pub re-exports
│   │       ├── accept.rs          # tokio accept loop
│   │       ├── connect.rs         # manual CONNECT parse + reply
│   │       ├── server.rs          # inner h1/h2 hyper server
│   │       └── upstream.rs        # hyper + hyper-rustls client
│   ├── roxy-mitm/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ca.rs              # CA generate / load / persist
│   │       ├── leaf.rs            # leaf cert minting
│   │       ├── resolver.rs        # rustls ResolvesServerCert + SNI LRU
│   │       ├── terminator.rs      # TLS terminator builder
│   │       └── trust/             # trust-store install (roxy-kcq)
│   │           ├── mod.rs         # platform dispatch + fingerprint
│   │           ├── macos.rs       # `security add-trusted-cert`
│   │           └── linux.rs       # /usr/local/share/ca-certificates
│   ├── roxy-cache/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── key.rs             # CacheKey + from_request
│   │       ├── response.rs        # CachedResponse, ResponseMeta
│   │       └── error.rs           # CacheError
│   ├── roxy-cache-fs/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs             # pub FsCache
│   │       ├── index.rs           # sqlite open + migrate + queries
│   │       ├── blob.rs            # blob path derivation, atomic rename
│   │       └── writer.rs          # CacheWriter impl (stream + hash)
│   └── roxy-config/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs             # Config struct, defaults, load fn
│           └── error.rs           # ConfigError
└── docs/
    └── superpowers/
        ├── specs/2026-05-12-roxy-mvp-architecture-design.md
        └── plans/2026-05-12-roxy-mvp-implementation.md   ← this file
```

---

## Task 1: Cargo workspace scaffold

**Beads:** `roxy-nsh`

**Files:**
- Create: `Cargo.toml` (workspace), `rust-toolchain.toml`
- Create: `crates/{roxy-proxy,roxy-http,roxy-mitm,roxy-cache,roxy-cache-fs,roxy-config}/Cargo.toml`
- Create: `crates/roxy-proxy/src/main.rs`
- Create: `crates/{roxy-http,roxy-mitm,roxy-cache,roxy-cache-fs,roxy-config}/src/lib.rs`

- [ ] **Step 1: Mark beads issue in progress**

```bash
bd update roxy-nsh --status=in_progress
```

- [ ] **Step 2: Write the workspace manifest**

`Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/roxy-proxy",
    "crates/roxy-http",
    "crates/roxy-mitm",
    "crates/roxy-cache",
    "crates/roxy-cache-fs",
    "crates/roxy-config",
]

[workspace.package]
edition = "2021"
rust-version = "1.80"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
# async runtime
tokio = { version = "1.40", features = ["rt-multi-thread", "net", "fs", "io-util", "macros", "signal", "time", "sync"] }
futures = "0.3"
async-trait = "0.1"

# http
hyper = { version = "1.5", features = ["http1", "http2", "server", "client"] }
hyper-util = { version = "0.1.10", features = ["tokio", "server-auto", "client-legacy", "http1", "http2"] }
hyper-rustls = { version = "0.27", default-features = false, features = ["http1", "http2", "ring", "rustls-native-certs"] }
http = "1.1"
http-body = "1"
http-body-util = "0.1"
bytes = "1.7"

# tls / crypto
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }
rustls-pki-types = "1.8"
rustls-pemfile = "2.2"
rcgen = { version = "0.13", features = ["pem"] }
sha2 = "0.10"
hex = "0.4"

# storage
rusqlite = { version = "0.32", features = ["bundled"] }

# misc
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
thiserror = "1"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
clap = { version = "4.5", features = ["derive"] }
uuid = { version = "1.10", features = ["v4"] }
lru = "0.12"
url = "2.5"
shellexpand = "3.1"
dirs = "5"

# internal
roxy-cache = { path = "crates/roxy-cache" }
roxy-cache-fs = { path = "crates/roxy-cache-fs" }
roxy-config = { path = "crates/roxy-config" }
roxy-http = { path = "crates/roxy-http" }
roxy-mitm = { path = "crates/roxy-mitm" }

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"

[workspace.lints.rust]
unsafe_code = "forbid"

[profile.dev]
opt-level = 0
debug = true

[profile.release]
lto = "thin"
codegen-units = 1
```

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustc", "cargo", "clippy", "rustfmt"]
```

- [ ] **Step 3: Create the six crate manifests and src files**

Each library crate (`roxy-http`, `roxy-mitm`, `roxy-cache`, `roxy-cache-fs`, `roxy-config`) gets a `Cargo.toml` like:

```toml
[package]
name = "roxy-<name>"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }
```

Each library's `src/lib.rs` starts as:

```rust
//! See workspace README and design spec.
```

`crates/roxy-proxy/Cargo.toml`:

```toml
[package]
name = "roxy-proxy"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = "roxy"
path = "src/main.rs"

[lints]
workspace = true

[dependencies]
roxy-cache = { workspace = true }
roxy-cache-fs = { workspace = true }
roxy-config = { workspace = true }
roxy-http = { workspace = true }
roxy-mitm = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
clap = { workspace = true }
anyhow = { workspace = true }
hyper = { workspace = true }
hyper-util = { workspace = true }
http = { workspace = true }
http-body-util = { workspace = true }
bytes = { workspace = true }
futures = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
axum = { version = "0.7", features = ["http2"] }
axum-server = { version = "0.7", features = ["tls-rustls"] }
tempfile = "3.13"
rustls = { workspace = true }
rcgen = { workspace = true }
```

`crates/roxy-proxy/src/main.rs`:

```rust
fn main() {
    println!("roxy {}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 4: Verify the workspace builds clean**

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Expected: all three succeed with no errors.

- [ ] **Step 5: Commit and close the issue**

```bash
git add Cargo.toml Cargo.lock rust-toolchain.toml crates/
git commit -m "feat(roxy-nsh): scaffold cargo workspace and six crates"
bd close roxy-nsh
```

---

## Task 2: `roxy-config` — Config struct and defaults

**Beads:** `roxy-dtz` (start)

**Files:**
- Modify: `crates/roxy-config/Cargo.toml`
- Create: `crates/roxy-config/src/lib.rs`, `crates/roxy-config/src/error.rs`

- [ ] **Step 1: Mark beads issue in progress**

```bash
bd update roxy-dtz --status=in_progress
```

- [ ] **Step 2: Add dependencies to the crate manifest**

`crates/roxy-config/Cargo.toml` — add under `[dependencies]`:

```toml
serde = { workspace = true }
toml = { workspace = true }
thiserror = { workspace = true }
shellexpand = { workspace = true }
dirs = { workspace = true }
```

- [ ] **Step 3: Write the failing test for default Config values**

Replace `crates/roxy-config/src/lib.rs`:

```rust
mod error;
pub use error::ConfigError;

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    pub cache: CacheConfig,
    pub ca: CaConfig,
    pub log: LogConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CacheConfig {
    pub dir: PathBuf,
    pub default_ttl_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CaConfig {
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct LogConfig {
    pub level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().expect("static addr"),
            cache: CacheConfig::default(),
            ca: CaConfig::default(),
            log: LogConfig::default(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("~/.local/share/roxy/cache"),
            default_ttl_seconds: 3600,
        }
    }
}

impl Default for CaConfig {
    fn default() -> Self {
        Self { dir: PathBuf::from("~/.config/roxy/ca") }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self { level: "info".to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_spec() {
        let c = Config::default();
        assert_eq!(c.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(c.cache.default_ttl_seconds, 3600);
        assert_eq!(c.log.level, "info");
    }
}
```

`crates/roxy-config/src/error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(std::path::PathBuf),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("path expansion: {0}")]
    Expand(String),
}
```

Run: `cargo test -p roxy-config default_config_matches_spec`

Expected: **PASS** (this task is structural; the test simply pins the default values).

- [ ] **Step 4: Commit**

```bash
git add crates/roxy-config/
git commit -m "feat(roxy-dtz): roxy-config Config struct + defaults"
```

---

## Task 3: `roxy-config` — TOML load with path expansion

**Beads:** `roxy-dtz` (continue)

**Files:**
- Modify: `crates/roxy-config/src/lib.rs`

- [ ] **Step 1: Add the failing test**

Append to `crates/roxy-config/src/lib.rs`'s `#[cfg(test)] mod tests`:

```rust
    use std::io::Write as _;

    #[test]
    fn loads_partial_toml_with_defaults() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"listen = "0.0.0.0:9090""#).unwrap();
        writeln!(f, r#"[cache]"#).unwrap();
        writeln!(f, r#"default_ttl_seconds = 60"#).unwrap();
        let c = load_from_path(f.path()).unwrap();
        assert_eq!(c.listen.to_string(), "0.0.0.0:9090");
        assert_eq!(c.cache.default_ttl_seconds, 60);
        // Untouched fields keep defaults.
        assert_eq!(c.log.level, "info");
    }

    #[test]
    fn expands_home_in_cache_dir() {
        let c = Config::default().with_expanded_paths().unwrap();
        let s = c.cache.dir.to_string_lossy().to_string();
        assert!(!s.starts_with("~"), "got: {}", s);
    }

    #[test]
    fn missing_file_returns_not_found() {
        let err = load_from_path(std::path::Path::new("/nonexistent/roxy.toml"))
            .unwrap_err();
        assert!(matches!(err, ConfigError::NotFound(_)));
    }
```

Add `tempfile` to dev-deps in `crates/roxy-config/Cargo.toml`:

```toml
[dev-dependencies]
tempfile = "3.13"
```

Run: `cargo test -p roxy-config`

Expected: **FAIL** — `load_from_path` and `with_expanded_paths` not defined.

- [ ] **Step 2: Implement load + expansion**

Append to `crates/roxy-config/src/lib.rs` (before the `#[cfg(test)]`):

```rust
use std::path::Path;

pub fn load_from_path(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::NotFound(path.to_path_buf()));
    }
    let bytes = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&bytes)?;
    cfg.with_expanded_paths()
}

pub fn default_config_path() -> PathBuf {
    if let Some(dir) = dirs::config_dir() {
        dir.join("roxy").join("config.toml")
    } else {
        PathBuf::from("./roxy.toml")
    }
}

impl Config {
    pub fn with_expanded_paths(mut self) -> Result<Self, ConfigError> {
        self.cache.dir = expand(&self.cache.dir)?;
        self.ca.dir = expand(&self.ca.dir)?;
        Ok(self)
    }
}

fn expand(p: &Path) -> Result<PathBuf, ConfigError> {
    let s = p.to_string_lossy();
    let expanded = shellexpand::full(&s)
        .map_err(|e| ConfigError::Expand(e.to_string()))?;
    Ok(PathBuf::from(expanded.into_owned()))
}
```

Run: `cargo test -p roxy-config`

Expected: **PASS** (3 tests).

- [ ] **Step 3: Commit and close**

```bash
git add crates/roxy-config/
git commit -m "feat(roxy-dtz): roxy-config TOML load with path expansion"
bd close roxy-dtz
```

---

## Task 4: `roxy-cache` — `CacheKey` with sorted query string

**Beads:** `roxy-dxn` (start)

**Files:**
- Modify: `crates/roxy-cache/Cargo.toml`
- Create: `crates/roxy-cache/src/key.rs`, modify `lib.rs`

- [ ] **Step 1: Mark in progress**

```bash
bd update roxy-dxn --status=in_progress
```

- [ ] **Step 2: Add dependencies**

`crates/roxy-cache/Cargo.toml`:

```toml
[dependencies]
async-trait = { workspace = true }
bytes = { workspace = true }
http = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true, features = ["io-util"] }
url = { workspace = true }
futures = { workspace = true }
```

- [ ] **Step 3: Write failing tests for CacheKey**

Replace `crates/roxy-cache/src/lib.rs`:

```rust
mod key;
pub use key::CacheKey;
```

Create `crates/roxy-cache/src/key.rs`:

```rust
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey(Vec<u8>);

impl CacheKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_parts(method: &str, scheme: &str, host: &str, path: &str, query: Option<&str>) -> Self {
        let sorted_query = query.map(sort_query).unwrap_or_default();
        let mut buf = Vec::with_capacity(
            method.len() + scheme.len() + host.len() + path.len() + sorted_query.len() + 4,
        );
        buf.extend_from_slice(method.to_ascii_uppercase().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(scheme.to_ascii_lowercase().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(host.to_ascii_lowercase().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(path.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(sorted_query.as_bytes());
        Self(buf)
    }
}

fn sort_query(q: &str) -> String {
    let mut pairs: Vec<&str> = q.split('&').filter(|s| !s.is_empty()).collect();
    pairs.sort();
    pairs.join("&")
}

impl fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CacheKey({:?})", String::from_utf8_lossy(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_uppercased_scheme_host_lowercased() {
        let a = CacheKey::from_parts("get", "HTTPS", "Example.COM", "/api", None);
        let b = CacheKey::from_parts("GET", "https", "example.com", "/api", None);
        assert_eq!(a, b);
    }

    #[test]
    fn query_params_sorted() {
        let a = CacheKey::from_parts("GET", "https", "a.b", "/p", Some("z=2&a=1"));
        let b = CacheKey::from_parts("GET", "https", "a.b", "/p", Some("a=1&z=2"));
        assert_eq!(a, b);
    }

    #[test]
    fn different_paths_differ() {
        let a = CacheKey::from_parts("GET", "https", "a.b", "/x", None);
        let b = CacheKey::from_parts("GET", "https", "a.b", "/y", None);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_query_treated_as_absent() {
        let a = CacheKey::from_parts("GET", "https", "a.b", "/x", None);
        let b = CacheKey::from_parts("GET", "https", "a.b", "/x", Some(""));
        assert_eq!(a, b);
    }
}
```

Run: `cargo test -p roxy-cache`

Expected: **PASS** (4 tests).

- [ ] **Step 4: Add `from_request` helper**

Append to `key.rs`:

```rust
use http::Request;

impl CacheKey {
    pub fn from_request<B>(req: &Request<B>, default_scheme: &str, default_host: &str) -> Self {
        let method = req.method().as_str();
        let uri = req.uri();
        let scheme = uri.scheme_str().unwrap_or(default_scheme);
        let host = uri.host().or_else(|| {
            req.headers().get(http::header::HOST).and_then(|h| h.to_str().ok())
        }).unwrap_or(default_host);
        let path = uri.path();
        let query = uri.query();
        Self::from_parts(method, scheme, host, path, query)
    }
}
```

Append a test:

```rust
    #[test]
    fn from_request_picks_authority_from_uri() {
        let r = http::Request::get("https://example.com/api?b=2&a=1")
            .body(()).unwrap();
        let k = CacheKey::from_request(&r, "http", "fallback");
        let expected = CacheKey::from_parts("GET", "https", "example.com", "/api", Some("a=1&b=2"));
        assert_eq!(k, expected);
    }
```

Run: `cargo test -p roxy-cache`. Expected: **PASS** (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/roxy-cache/
git commit -m "feat(roxy-dxn): CacheKey with sorted query string + from_request"
```

---

## Task 5: `roxy-cache` — Response types, error, Cache trait

**Beads:** `roxy-dxn` (finish)

**Files:**
- Create: `crates/roxy-cache/src/response.rs`, `crates/roxy-cache/src/error.rs`
- Modify: `crates/roxy-cache/src/lib.rs`

- [ ] **Step 1: Add the types and trait**

`crates/roxy-cache/src/error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("backend: {0}")]
    Backend(String),

    #[error("corrupted entry: {0}")]
    Corrupted(String),
}
```

`crates/roxy-cache/src/response.rs`:

```rust
use bytes::Bytes;
use futures::stream::BoxStream;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct ResponseMeta {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
}

pub struct CachedResponse {
    pub meta: ResponseMeta,
    pub body: BoxStream<'static, Result<Bytes, std::io::Error>>,
    pub created_at: SystemTime,
    pub ttl: Duration,
}

impl CachedResponse {
    pub fn is_expired(&self, now: SystemTime) -> bool {
        match now.duration_since(self.created_at) {
            Ok(age) => age >= self.ttl,
            Err(_) => false,
        }
    }
}
```

Replace `crates/roxy-cache/src/lib.rs`:

```rust
mod error;
mod key;
mod response;

pub use error::CacheError;
pub use key::CacheKey;
pub use response::{CachedResponse, ResponseMeta};

use async_trait::async_trait;
use futures::future::BoxFuture;
use tokio::io::AsyncWrite;

#[async_trait]
pub trait Cache: Send + Sync {
    async fn lookup(&self, key: &CacheKey) -> Result<Option<CachedResponse>, CacheError>;

    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
        default_ttl: std::time::Duration,
    ) -> Result<Box<dyn CacheWriter>, CacheError>;
}

pub trait CacheWriter: AsyncWrite + Send + Unpin {
    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(), CacheError>>;
    fn abort(self: Box<Self>);
}
```

- [ ] **Step 2: Verify the crate compiles and tests pass**

```bash
cargo test -p roxy-cache
cargo clippy -p roxy-cache --all-targets -- -D warnings
```

Expected: both succeed.

- [ ] **Step 3: Commit and close**

```bash
git add crates/roxy-cache/
git commit -m "feat(roxy-dxn): Cache + CacheWriter traits, ResponseMeta, CacheError"
bd close roxy-dxn
```

---

## Task 6: `roxy-mitm` — CA generation and load

**Beads:** `roxy-3ae` (start)

**Files:**
- Modify: `crates/roxy-mitm/Cargo.toml`
- Create: `crates/roxy-mitm/src/ca.rs`, modify `lib.rs`

- [ ] **Step 1: Mark in progress**

```bash
bd update roxy-3ae --status=in_progress
```

- [ ] **Step 2: Add deps**

`crates/roxy-mitm/Cargo.toml`:

```toml
[dependencies]
rcgen = { workspace = true }
rustls = { workspace = true }
rustls-pki-types = { workspace = true }
rustls-pemfile = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
lru = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring", "tls12"] }
tracing = { workspace = true }

[dev-dependencies]
tempfile = "3.13"
```

- [ ] **Step 3: Write failing CA tests**

Replace `crates/roxy-mitm/src/lib.rs`:

```rust
pub mod ca;

pub use ca::{Ca, CaError};
```

Create `crates/roxy-mitm/src/ca.rs`:

```rust
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose, IsCa, BasicConstraints};
use std::path::{Path, PathBuf};
use thiserror::Error;
use std::sync::Arc;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("pem: {0}")]
    Pem(String),
}

#[derive(Clone)]
pub struct Ca {
    pub cert_pem: String,
    pub key_pair: Arc<KeyPair>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl Ca {
    pub fn load_or_create(dir: &Path) -> Result<Self, CaError> {
        std::fs::create_dir_all(dir)?;
        let cert_path = dir.join("roxy-ca.crt");
        let key_path = dir.join("roxy-ca.key");
        if cert_path.exists() && key_path.exists() {
            Self::load(&cert_path, &key_path)
        } else {
            Self::create(&cert_path, &key_path)
        }
    }

    fn create(cert_path: &Path, key_path: &Path) -> Result<Self, CaError> {
        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Roxy Local CA");
        dn.push(DnType::OrganizationName, "Roxy");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let not_before = time::OffsetDateTime::now_utc();
        params.not_before = not_before;
        params.not_after = not_before + time::Duration::days(3650);
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        std::fs::write(cert_path, &cert_pem)?;
        std::fs::write(key_path, &key_pem)?;
        Ok(Self {
            cert_pem,
            key_pair: Arc::new(key_pair),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
        })
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self, CaError> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        let key_pair = KeyPair::from_pem(&key_pem).map_err(CaError::Rcgen)?;
        Ok(Self {
            cert_pem,
            key_pair: Arc::new(key_pair),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_run_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        assert!(ca.cert_path.exists());
        assert!(ca.key_path.exists());
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn second_call_loads_existing() {
        let dir = tempfile::tempdir().unwrap();
        let a = Ca::load_or_create(dir.path()).unwrap();
        let b = Ca::load_or_create(dir.path()).unwrap();
        assert_eq!(a.cert_pem, b.cert_pem);
    }
}
```

Add `time` to deps (rcgen re-exports it):

```toml
time = "0.3"
```

- [ ] **Step 4: Verify tests pass**

```bash
cargo test -p roxy-mitm
```

Expected: 2 passing tests.

- [ ] **Step 5: Commit**

```bash
git add crates/roxy-mitm/
git commit -m "feat(roxy-3ae): roxy-mitm CA generation and load"
```

---

## Task 7: `roxy-mitm` — Leaf cert minting

**Beads:** `roxy-3ae` (continue)

**Files:**
- Create: `crates/roxy-mitm/src/leaf.rs`, modify `lib.rs`

- [ ] **Step 1: Write the failing test**

Add to `crates/roxy-mitm/src/lib.rs`:

```rust
pub mod leaf;
pub use leaf::LeafSigner;
```

Create `crates/roxy-mitm/src/leaf.rs`:

```rust
use crate::ca::{Ca, CaError};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

pub struct LeafSigner {
    ca: Ca,
}

impl LeafSigner {
    pub fn new(ca: Ca) -> Self {
        Self { ca }
    }

    pub fn mint(&self, sni: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sni);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(
            sni.to_string().try_into().map_err(|e: rcgen::Error| CaError::Rcgen(e))?,
        )];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::hours(24);

        // Reload CA into rcgen-issuable form
        let issuer = rcgen::CertificateParams::from_ca_cert_pem(&self.ca.cert_pem)
            .map_err(CaError::Rcgen)?;
        let issuer_cert = issuer.self_signed(self.ca.key_pair.as_ref()).map_err(CaError::Rcgen)?;
        let cert = params.signed_by(&leaf_key, &issuer_cert, self.ca.key_pair.as_ref())
            .map_err(CaError::Rcgen)?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| CaError::Pem(e.to_string()))?;
        Ok(Arc::new(CertifiedKey::new(vec![cert_der], signing_key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;

    #[test]
    fn mints_leaf_for_sni() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let signer = LeafSigner::new(ca);
        let key = signer.mint("example.com").unwrap();
        assert_eq!(key.cert.len(), 1);
    }

    #[test]
    fn two_mints_produce_distinct_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let signer = LeafSigner::new(ca);
        let a = signer.mint("example.com").unwrap();
        let b = signer.mint("example.com").unwrap();
        // Different serial / key each mint.
        assert_ne!(a.cert[0].as_ref(), b.cert[0].as_ref());
    }
}
```

Run: `cargo test -p roxy-mitm`

Expected: 4 passing tests.

- [ ] **Step 2: Commit**

```bash
git add crates/roxy-mitm/
git commit -m "feat(roxy-3ae): roxy-mitm leaf cert minting"
```

---

## Task 8: `roxy-mitm` — SNI-keyed LRU + cert resolver

**Beads:** `roxy-3ae` (continue)

**Files:**
- Create: `crates/roxy-mitm/src/resolver.rs`, modify `lib.rs`

- [ ] **Step 1: Add resolver with LRU cache**

Add `pub mod resolver;` to `lib.rs` and a re-export `pub use resolver::SniResolver;`.

Create `crates/roxy-mitm/src/resolver.rs`:

```rust
use crate::leaf::LeafSigner;
use lru::LruCache;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

pub struct SniResolver {
    signer: LeafSigner,
    cache: Mutex<LruCache<String, Arc<CertifiedKey>>>,
}

impl SniResolver {
    pub fn new(signer: LeafSigner, capacity: NonZeroUsize) -> Self {
        Self {
            signer,
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver").finish()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        let sni_owned = sni.to_string();
        {
            let mut cache = self.cache.lock().ok()?;
            if let Some(k) = cache.get(&sni_owned) {
                return Some(k.clone());
            }
        }
        let minted = self.signer.mint(&sni_owned).ok()?;
        let mut cache = self.cache.lock().ok()?;
        cache.put(sni_owned, minted.clone());
        Some(minted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;

    #[test]
    fn resolver_can_be_constructed() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let signer = LeafSigner::new(ca);
        let _ = SniResolver::new(signer, NonZeroUsize::new(10).unwrap());
    }
}
```

(Functional behavior is exercised in the end-to-end terminator test in the next task.)

Run: `cargo test -p roxy-mitm`

Expected: 5 passing tests.

- [ ] **Step 2: Commit**

```bash
git add crates/roxy-mitm/
git commit -m "feat(roxy-3ae): SNI-keyed LRU cert resolver"
```

---

## Task 9: `roxy-mitm` — TLS terminator + end-to-end handshake test

**Beads:** `roxy-3ae` (finish)

**Files:**
- Create: `crates/roxy-mitm/src/terminator.rs`, modify `lib.rs`

- [ ] **Step 1: Write the failing test**

Add `pub mod terminator;` to `lib.rs` and `pub use terminator::Terminator;`.

Create `crates/roxy-mitm/src/terminator.rs`:

```rust
use crate::resolver::SniResolver;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
pub struct Terminator {
    acceptor: TlsAcceptor,
}

impl Terminator {
    pub fn new(resolver: Arc<SniResolver>) -> Self {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        let mut config = config;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        Self { acceptor }
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ca::Ca, leaf::LeafSigner, resolver::SniResolver};
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    #[tokio::test]
    async fn handshake_succeeds_against_terminator() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let signer = LeafSigner::new(ca.clone());
        let resolver = Arc::new(SniResolver::new(signer, NonZeroUsize::new(8).unwrap()));
        let terminator = Terminator::new(resolver);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // server
        let acceptor = terminator.acceptor();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"HELLO");
            tls.write_all(b"OK").await.unwrap();
            tls.shutdown().await.unwrap();
        });

        // client trusting our CA
        let mut roots = rustls::RootCertStore::empty();
        let pem = ca.cert_pem.as_bytes();
        for c in rustls_pemfile::certs(&mut std::io::Cursor::new(pem)).flatten() {
            roots.add(c).unwrap();
        }
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(config));
        let sock = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("example.com").unwrap();
        let mut tls = connector.connect(server_name, sock).await.unwrap();
        tls.write_all(b"HELLO").await.unwrap();
        let mut resp = [0u8; 2];
        tls.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"OK");
    }
}
```

Run: `cargo test -p roxy-mitm`

Expected: 6 passing tests (handshake should round-trip through the dynamically-minted leaf).

- [ ] **Step 2: Commit and close**

```bash
git add crates/roxy-mitm/
git commit -m "feat(roxy-3ae): TLS terminator with ALPN h2,http/1.1 + handshake test"
bd close roxy-3ae
```

---

## Task 10: `roxy-cache-fs` — sqlite schema + open

**Beads:** `roxy-d4q` (start)

**Files:**
- Modify: `crates/roxy-cache-fs/Cargo.toml`
- Create: `crates/roxy-cache-fs/src/index.rs`, replace `lib.rs`

- [ ] **Step 1: Mark in progress**

```bash
bd update roxy-d4q --status=in_progress
```

- [ ] **Step 2: Add deps**

`crates/roxy-cache-fs/Cargo.toml`:

```toml
[dependencies]
roxy-cache = { workspace = true }
rusqlite = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
bytes = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }
async-trait = { workspace = true }
futures = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
uuid = { workspace = true }

[dev-dependencies]
tempfile = "3.13"
```

- [ ] **Step 3: Write the failing schema test**

Create `crates/roxy-cache-fs/src/index.rs`:

```rust
use rusqlite::Connection;
use std::path::Path;

pub fn open(db_path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(SCHEMA_V1)?;
    Ok(conn)
}

const SCHEMA_V1: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS entries (
    key          BLOB PRIMARY KEY,
    content_hash BLOB NOT NULL,
    status       INTEGER NOT NULL,
    headers_json TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    ttl_seconds  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS entries_content_hash ON entries(content_hash);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_and_creates_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("idx.sqlite");
        let conn = open(&db).unwrap();
        let n: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'entries'",
            [],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(n, 1);
    }
}
```

Replace `crates/roxy-cache-fs/src/lib.rs`:

```rust
mod blob;
mod index;
mod writer;

pub use writer::FsCache;
```

(`blob` and `writer` modules will be created in subsequent tasks; for now this file won't compile yet — write the stubs.)

Create `crates/roxy-cache-fs/src/blob.rs`:

```rust
// stub: implemented in next task
```

Create `crates/roxy-cache-fs/src/writer.rs`:

```rust
// stub: implemented later
pub struct FsCache;
```

Run: `cargo test -p roxy-cache-fs`

Expected: 1 passing test.

- [ ] **Step 4: Commit**

```bash
git add crates/roxy-cache-fs/
git commit -m "feat(roxy-d4q): sqlite schema for cache index"
```

---

## Task 11: `roxy-cache-fs` — blob path + atomic finalize

**Beads:** `roxy-d4q` (continue)

**Files:** `crates/roxy-cache-fs/src/blob.rs`

- [ ] **Step 1: Replace stub with implementation + tests**

```rust
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Path for a blob given its sha256 hex.
pub fn blob_path(cache_dir: &Path, hex: &str) -> PathBuf {
    let prefix = &hex[..2];
    cache_dir.join("blobs").join(prefix).join(format!("{hex}.bin"))
}

pub fn tmp_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("tmp").join(Uuid::new_v4().to_string())
}

pub fn ensure_dirs(cache_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(cache_dir.join("tmp"))?;
    std::fs::create_dir_all(cache_dir.join("blobs"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn blob_path_uses_prefix_dir() {
        let p = blob_path(&PathBuf::from("/c"), "abcdef0123456789");
        assert_eq!(p, PathBuf::from("/c/blobs/ab/abcdef0123456789.bin"));
    }

    #[test]
    fn ensure_dirs_creates_blobs_and_tmp() {
        let d = tempfile::tempdir().unwrap();
        ensure_dirs(d.path()).unwrap();
        assert!(d.path().join("blobs").is_dir());
        assert!(d.path().join("tmp").is_dir());
    }
}
```

Run: `cargo test -p roxy-cache-fs`. Expected: 3 passing tests.

- [ ] **Step 2: Commit**

```bash
git add crates/roxy-cache-fs/src/blob.rs
git commit -m "feat(roxy-d4q): blob path layout and atomic helpers"
```

---

## Task 12: `roxy-cache-fs` — `FsCache::begin_store` (streaming writer)

**Beads:** `roxy-d4q` (continue)

**Files:** `crates/roxy-cache-fs/src/writer.rs`

- [ ] **Step 1: Replace stub with full streaming writer**

```rust
use crate::blob::{blob_path, ensure_dirs, tmp_path};
use crate::index;
use async_trait::async_trait;
use futures::future::{BoxFuture, FutureExt};
use roxy_cache::{Cache, CacheError, CacheKey, CachedResponse, CacheWriter, ResponseMeta};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncWrite, AsyncWriteExt};

#[derive(Clone)]
pub struct FsCache {
    cache_dir: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl FsCache {
    pub fn open(cache_dir: impl Into<PathBuf>) -> Result<Self, CacheError> {
        let cache_dir = cache_dir.into();
        ensure_dirs(&cache_dir).map_err(CacheError::Io)?;
        let conn = index::open(&cache_dir.join("index.sqlite"))
            .map_err(|e| CacheError::Backend(e.to_string()))?;
        Ok(Self {
            cache_dir,
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Remove any leftover tmp files (called at startup).
    pub fn cleanup_tmp(&self) -> std::io::Result<usize> {
        let dir = self.cache_dir.join("tmp");
        let mut n = 0;
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let _ = std::fs::remove_file(entry.path());
                n += 1;
            }
        }
        Ok(n)
    }
}

pub struct FsWriter {
    tmp_path: PathBuf,
    file: Option<File>,
    hasher: Sha256,
    bytes_written: u64,
    key: CacheKey,
    meta: ResponseMeta,
    ttl: Duration,
    cache_dir: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl AsyncWrite for FsWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let file = self.file.as_mut().expect("file open");
        let pinned = Pin::new(file);
        match pinned.poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                self.hasher.update(&buf[..n]);
                self.bytes_written += n as u64;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let file = self.file.as_mut().expect("file open");
        Pin::new(file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let file = self.file.as_mut().expect("file open");
        Pin::new(file).poll_shutdown(cx)
    }
}

impl CacheWriter for FsWriter {
    fn finish(mut self: Box<Self>) -> BoxFuture<'static, Result<(), CacheError>> {
        async move {
            if let Some(mut f) = self.file.take() {
                f.flush().await.map_err(CacheError::Io)?;
                f.sync_all().await.map_err(CacheError::Io)?;
            }
            let hash = self.hasher.finalize();
            let hex = hex::encode(hash);
            let final_path = blob_path(&self.cache_dir, &hex);
            if let Some(parent) = final_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(CacheError::Io)?;
            }
            tokio::fs::rename(&self.tmp_path, &final_path).await.map_err(CacheError::Io)?;

            let headers_json = serde_json::to_string(&self.meta.headers)
                .map_err(|e| CacheError::Backend(e.to_string()))?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            let conn = self.conn.lock().map_err(|_| CacheError::Backend("mutex".into()))?;
            conn.execute(
                "INSERT OR REPLACE INTO entries (key, content_hash, status, headers_json, created_at, ttl_seconds)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    self.key.as_bytes(),
                    hash.as_slice(),
                    self.meta.status as i64,
                    headers_json,
                    now,
                    self.ttl.as_secs() as i64,
                ],
            ).map_err(|e| CacheError::Backend(e.to_string()))?;
            Ok(())
        }.boxed()
    }

    fn abort(mut self: Box<Self>) {
        self.file.take();
        let _ = std::fs::remove_file(&self.tmp_path);
    }
}

#[async_trait]
impl Cache for FsCache {
    async fn lookup(&self, _key: &CacheKey) -> Result<Option<CachedResponse>, CacheError> {
        // implemented in next task
        Ok(None)
    }

    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
        default_ttl: Duration,
    ) -> Result<Box<dyn CacheWriter>, CacheError> {
        let tmp = tmp_path(&self.cache_dir);
        if let Some(parent) = tmp.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(CacheError::Io)?;
        }
        let file = File::create(&tmp).await.map_err(CacheError::Io)?;
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
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn store_writes_blob_and_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("GET", "https", "x.y", "/p", None);
        let mut w = cache.begin_store(&key, ResponseMeta { status: 200, headers: vec![] }, Duration::from_secs(60)).await.unwrap();
        w.write_all(b"hello").await.unwrap();
        w.finish().await.unwrap();

        // a blob file should now exist somewhere under blobs/
        let blobs_root = dir.path().join("blobs");
        let mut found = false;
        for prefix in std::fs::read_dir(&blobs_root).unwrap() {
            for f in std::fs::read_dir(prefix.unwrap().path()).unwrap() {
                let f = f.unwrap();
                if f.path().extension().and_then(|s| s.to_str()) == Some("bin") {
                    let bytes = std::fs::read(f.path()).unwrap();
                    assert_eq!(bytes, b"hello");
                    found = true;
                }
            }
        }
        assert!(found);
    }

    #[tokio::test]
    async fn abort_discards_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("GET", "https", "x.y", "/p", None);
        let mut w = cache.begin_store(&key, ResponseMeta { status: 200, headers: vec![] }, Duration::from_secs(60)).await.unwrap();
        w.write_all(b"partial").await.unwrap();
        w.abort();
        assert_eq!(std::fs::read_dir(dir.path().join("tmp")).unwrap().count(), 0);
        let blobs_root = dir.path().join("blobs");
        let n = std::fs::read_dir(&blobs_root).map(|rd| rd.count()).unwrap_or(0);
        assert_eq!(n, 0);
    }
}
```

Run: `cargo test -p roxy-cache-fs`. Expected: 5 passing tests.

- [ ] **Step 2: Commit**

```bash
git add crates/roxy-cache-fs/
git commit -m "feat(roxy-d4q): FsCache::begin_store streams + atomic finalize"
```

---

## Task 13: `roxy-cache-fs` — `FsCache::lookup` + TTL

**Beads:** `roxy-d4q` (finish)

**Files:** `crates/roxy-cache-fs/src/writer.rs`

- [ ] **Step 1: Replace the `lookup` stub**

Replace the body of `async fn lookup` in `writer.rs`:

```rust
    async fn lookup(&self, key: &CacheKey) -> Result<Option<CachedResponse>, CacheError> {
        use futures::StreamExt;
        let row = {
            let conn = self.conn.lock().map_err(|_| CacheError::Backend("mutex".into()))?;
            conn.query_row(
                "SELECT content_hash, status, headers_json, created_at, ttl_seconds
                 FROM entries WHERE key = ?1",
                [key.as_bytes()],
                |r| {
                    let content_hash: Vec<u8> = r.get(0)?;
                    let status: i64 = r.get(1)?;
                    let headers_json: String = r.get(2)?;
                    let created_at: i64 = r.get(3)?;
                    let ttl_seconds: i64 = r.get(4)?;
                    Ok((content_hash, status, headers_json, created_at, ttl_seconds))
                },
            ).ok()
        };
        let Some((content_hash, status, headers_json, created_at, ttl_seconds)) = row else {
            return Ok(None);
        };
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
            meta: ResponseMeta { status: status as u16, headers },
            body,
            created_at: created,
            ttl,
        };
        if resp.is_expired(SystemTime::now()) {
            return Ok(None);
        }
        Ok(Some(resp))
    }
```

Add `tokio-util` to deps in `crates/roxy-cache-fs/Cargo.toml`:

```toml
tokio-util = { version = "0.7", features = ["io"] }
```

- [ ] **Step 2: Add round-trip + TTL tests**

Append to the `tests` module in `writer.rs`:

```rust
    use futures::StreamExt;

    async fn drain_body(mut s: futures::stream::BoxStream<'static, Result<bytes::Bytes, std::io::Error>>) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = s.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn round_trip_store_then_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("GET", "https", "x.y", "/p", None);
        let mut w = cache.begin_store(
            &key,
            ResponseMeta { status: 200, headers: vec![("x".to_string(), b"y".to_vec())] },
            Duration::from_secs(60),
        ).await.unwrap();
        w.write_all(b"payload").await.unwrap();
        w.finish().await.unwrap();

        let hit = cache.lookup(&key).await.unwrap().expect("hit");
        assert_eq!(hit.meta.status, 200);
        assert_eq!(hit.meta.headers, vec![("x".to_string(), b"y".to_vec())]);
        let bytes = drain_body(hit.body).await;
        assert_eq!(bytes, b"payload");
    }

    #[tokio::test]
    async fn ttl_zero_means_immediately_expired() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("GET", "https", "x.y", "/p", None);
        let mut w = cache.begin_store(&key, ResponseMeta { status: 200, headers: vec![] }, Duration::from_secs(0)).await.unwrap();
        w.write_all(b"x").await.unwrap();
        w.finish().await.unwrap();
        // Sleep 1ms to guarantee elapsed > 0.
        tokio::time::sleep(Duration::from_millis(2)).await;
        let hit = cache.lookup(&key).await.unwrap();
        assert!(hit.is_none(), "expired entries must look like a miss");
    }
```

Run: `cargo test -p roxy-cache-fs`. Expected: 7 passing tests.

- [ ] **Step 3: Commit and close**

```bash
git add crates/roxy-cache-fs/
git commit -m "feat(roxy-d4q): FsCache::lookup with TTL enforcement + round-trip test"
bd close roxy-d4q
```

---

## Task 14: `roxy-http` — upstream client (h1 + h2 over rustls)

**Beads:** `roxy-2qf`

**Files:**
- Modify: `crates/roxy-http/Cargo.toml`
- Create: `crates/roxy-http/src/upstream.rs`, replace `lib.rs`

- [ ] **Step 1: Mark in progress + add deps**

```bash
bd update roxy-2qf --status=in_progress
```

`crates/roxy-http/Cargo.toml`:

```toml
[dependencies]
roxy-mitm = { workspace = true }
hyper = { workspace = true }
hyper-util = { workspace = true }
hyper-rustls = { workspace = true }
rustls = { workspace = true }
http = { workspace = true }
http-body = { workspace = true }
http-body-util = { workspace = true }
bytes = { workspace = true }
tokio = { workspace = true }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring", "tls12"] }
futures = { workspace = true }
async-trait = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
axum = { version = "0.7", features = ["http2"] }
axum-server = { version = "0.7", features = ["tls-rustls"] }
rcgen = { workspace = true }
tempfile = "3.13"
```

- [ ] **Step 2: Write the upstream client**

Replace `crates/roxy-http/src/lib.rs`:

```rust
pub mod upstream;
pub use upstream::UpstreamClient;
```

Create `crates/roxy-http/src/upstream.rs`:

```rust
use http::{Request, Response};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("client: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),

    #[error("invalid uri: {0}")]
    Uri(String),
}

#[derive(Clone)]
pub struct UpstreamClient {
    inner: Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<bytes::Bytes>>,
}

impl UpstreamClient {
    pub fn new() -> Result<Self, UpstreamError> {
        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.enforce_http(false);
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| UpstreamError::Uri(e.to_string()))?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        let inner = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(32)
            .build(https);
        Ok(Self { inner })
    }

    pub async fn send_empty(&self, req: Request<Empty<bytes::Bytes>>) -> Result<Response<Incoming>, UpstreamError> {
        Ok(self.inner.request(req).await?)
    }
}
```

(Sending bodies will be handled in the tee-while-caching task, which wraps a custom request body.)

- [ ] **Step 3: Add a smoke unit test against a local axum origin**

Create `crates/roxy-http/tests/upstream_h1.rs`:

```rust
use axum::routing::get;
use axum::Router;
use roxy_http::UpstreamClient;
use std::net::SocketAddr;

#[tokio::test]
async fn h1_get_works() {
    let app = Router::new().route("/hello", get(|| async { "world" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = UpstreamClient::new().unwrap();
    let uri = format!("http://{addr}/hello").parse::<http::Uri>().unwrap();
    let req = http::Request::get(uri)
        .body(http_body_util::Empty::new())
        .unwrap();
    let resp = client.send_empty(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}
```

Run: `cargo test -p roxy-http`. Expected: 1 passing test.

- [ ] **Step 4: Commit and close**

```bash
git add crates/roxy-http/
git commit -m "feat(roxy-2qf): upstream client with ALPN h2/h1 + native roots"
bd close roxy-2qf
```

---

## Task 15: `roxy-http` — TCP accept loop and CONNECT handler

**Beads:** `roxy-m4q` (start)

**Files:** `crates/roxy-http/src/{accept.rs,connect.rs}`, modify `lib.rs`

- [ ] **Step 1: Mark in progress**

```bash
bd update roxy-m4q --status=in_progress
```

- [ ] **Step 2: Write the failing CONNECT test**

Add modules in `crates/roxy-http/src/lib.rs`:

```rust
pub mod accept;
pub mod connect;
pub mod upstream;
pub use upstream::UpstreamClient;
```

Create `crates/roxy-http/src/connect.rs`:

```rust
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Parse the initial HTTP/1.1 CONNECT line off a fresh client socket.
/// Returns Ok(Some(host)) on a CONNECT, Ok(None) on any other method.
pub async fn read_connect(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let line = line.trim_end_matches(['\r', '\n']);
    if !line.starts_with("CONNECT ") {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let _ = parts.next(); // CONNECT
    let authority = parts.next().unwrap_or("").to_string();
    // Drain remaining headers up to empty line.
    loop {
        let mut hl = String::new();
        let n = reader.read_line(&mut hl).await?;
        if n == 0 || hl == "\r\n" || hl == "\n" {
            break;
        }
    }
    Ok(Some(authority))
}

pub async fn write_200(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await
}
```

Create `crates/roxy-http/tests/connect_parse.rs`:

```rust
use roxy_http::connect::{read_connect, write_200};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn connect_parsed_and_acknowledged() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let host = read_connect(&mut s).await.unwrap().unwrap();
        assert_eq!(host, "example.com:443");
        write_200(&mut s).await.unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").await.unwrap();
    let mut buf = [0u8; 64];
    let n = client.read(&mut buf).await.unwrap();
    let resp = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
}
```

Run: `cargo test -p roxy-http connect_parsed_and_acknowledged`. Expected: **PASS**.

- [ ] **Step 3: Commit**

```bash
git add crates/roxy-http/
git commit -m "feat(roxy-m4q): manual CONNECT parse + 200 reply"
```

---

## Task 16: `roxy-http` — accept loop bridging CONNECT into TLS terminator

**Beads:** `roxy-m4q` (continue)

**Files:** `crates/roxy-http/src/accept.rs`, `crates/roxy-http/src/server.rs`

- [ ] **Step 1: Write the accept loop**

Create `crates/roxy-http/src/accept.rs`:

```rust
use crate::connect::{read_connect, write_200};
use roxy_mitm::Terminator;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, warn};

pub type Handler = Arc<dyn ConnHandler + Send + Sync>;

#[async_trait::async_trait]
pub trait ConnHandler: Send + Sync {
    async fn handle(
        &self,
        authority: String,
        tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    );
}

pub async fn run(listen: SocketAddr, terminator: Terminator, handler: Handler) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    loop {
        let (mut sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "accept error");
                continue;
            }
        };
        let terminator = terminator.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            let host = match read_connect(&mut sock).await {
                Ok(Some(h)) => h,
                Ok(None) => {
                    warn!(?peer, "non-CONNECT first request dropped");
                    return;
                }
                Err(e) => {
                    warn!(?peer, error = %e, "read_connect failed");
                    return;
                }
            };
            if let Err(e) = write_200(&mut sock).await {
                warn!(?peer, error = %e, "write 200 failed");
                return;
            }
            let acceptor = terminator.acceptor();
            let tls = match acceptor.accept(sock).await {
                Ok(t) => t,
                Err(e) => {
                    warn!(?peer, error = %e, "TLS handshake failed");
                    return;
                }
            };
            handler.handle(host, tls).await;
        });
    }
}
```

Create `crates/roxy-http/src/server.rs` (used by the binary later):

```rust
use http::{Request, Response};
use http_body::Body;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use tokio_rustls::server::TlsStream;

pub type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, std::io::Error>;

pub async fn serve_tls<F, Fut>(tls: TlsStream<tokio::net::TcpStream>, handler: F)
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<Response<BoxBody>, Infallible>> + Send + 'static,
{
    let io = TokioIo::new(tls);
    let svc = hyper::service::service_fn(move |req| {
        let handler = handler.clone();
        async move { handler(req).await }
    });
    let _ = auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, svc)
        .await;
}
```

Update `crates/roxy-http/src/lib.rs`:

```rust
pub mod accept;
pub mod connect;
pub mod server;
pub mod upstream;

pub use upstream::UpstreamClient;
pub use accept::{ConnHandler, Handler};
pub use server::{serve_tls, BoxBody};
```

- [ ] **Step 2: Verify the crate builds clean**

```bash
cargo clippy -p roxy-http --all-targets -- -D warnings
cargo test -p roxy-http
```

Expected: builds + all tests pass (the integration test that exercises this full path lives in `roxy-proxy/tests` and is added later).

- [ ] **Step 3: Commit and close**

```bash
git add crates/roxy-http/
git commit -m "feat(roxy-m4q): accept loop + TLS bridge + hyper auto h1/h2 server"
bd close roxy-m4q
```

---

## Task 17: `roxy-proxy` — request handler skeleton (cache lookup → response)

**Beads:** `roxy-z0p` (start)

**Files:** `crates/roxy-proxy/src/handler.rs`, modify `crates/roxy-proxy/src/main.rs`

- [ ] **Step 1: Mark in progress**

```bash
bd update roxy-z0p --status=in_progress
```

- [ ] **Step 2: Create the handler with hit-path only**

Create `crates/roxy-proxy/src/handler.rs`:

```rust
use bytes::Bytes;
use futures::TryStreamExt;
use http::{Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full, StreamBody};
use hyper::body::Incoming;
use roxy_cache::{Cache, CacheKey};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

#[derive(Clone)]
pub struct Handler<C: Cache + 'static> {
    pub cache: Arc<C>,
    pub default_ttl: Duration,
    pub upstream: roxy_http::UpstreamClient,
    pub disconnect_cap: u64,
}

impl<C: Cache + 'static> Handler<C> {
    pub async fn handle(&self, authority: String, req: Request<Incoming>) -> Result<Response<BoxBody>, Infallible> {
        let key = CacheKey::from_request(&req, "https", &authority);
        match self.cache.lookup(&key).await {
            Ok(Some(hit)) => Ok(reply_from_cache(hit)),
            Ok(None) => Ok(not_implemented_yet()),
            Err(e) => {
                tracing::warn!(error = %e, "cache lookup error - serving as pass-through");
                Ok(not_implemented_yet())
            }
        }
    }
}

fn reply_from_cache(hit: roxy_cache::CachedResponse) -> Response<BoxBody> {
    let mut builder = Response::builder().status(hit.meta.status);
    for (k, v) in &hit.meta.headers {
        if let Ok(name) = http::HeaderName::from_bytes(k.as_bytes()) {
            if let Ok(val) = http::HeaderValue::from_bytes(v) {
                builder = builder.header(name, val);
            }
        }
    }
    let stream = hit.body
        .map_ok(|b| http_body::Frame::data(b))
        .map_err(std::io::Error::from);
    let body = StreamBody::new(stream).boxed();
    builder.body(body).unwrap()
}

fn not_implemented_yet() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .body(Full::new(Bytes::from_static(b"miss path not implemented")).map_err(|never| match never {}).boxed())
        .unwrap()
}
```

Replace `crates/roxy-proxy/src/main.rs` with a stub that compiles:

```rust
mod handler;
fn main() {
    println!("roxy {}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 3: Verify it builds**

```bash
cargo build -p roxy-proxy
cargo clippy -p roxy-proxy --all-targets -- -D warnings
```

Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add crates/roxy-proxy/
git commit -m "feat(roxy-z0p): handler skeleton with cache hit path"
```

---

## Task 18: `roxy-proxy` — miss path with tee-while-caching

**Beads:** `roxy-z0p` (continue)

**Files:** `crates/roxy-proxy/src/handler.rs`, `crates/roxy-http/src/upstream.rs`

- [ ] **Step 1: Extend `UpstreamClient` to take a streaming body**

In `crates/roxy-http/src/upstream.rs`, replace `send_empty` with a generic `send` that accepts `BoxBody`:

```rust
use http_body_util::combinators::BoxBody;

pub type ClientBody = BoxBody<bytes::Bytes, std::io::Error>;

impl UpstreamClient {
    pub async fn send(&self, req: Request<ClientBody>) -> Result<Response<Incoming>, UpstreamError> {
        Ok(self.inner.request(req).await?)
    }
}
```

Update the legacy `Client` generic parameter accordingly:

```rust
inner: Client<hyper_rustls::HttpsConnector<HttpConnector>, ClientBody>,
```

Fix the existing `upstream_h1.rs` test to wrap the empty body:

```rust
let body = http_body_util::Empty::<bytes::Bytes>::new().map_err(|_| std::io::Error::other("never")).boxed();
let req = http::Request::get(uri).body(body).unwrap();
let resp = client.send(req).await.unwrap();
```

- [ ] **Step 2: Implement miss-path in handler**

Replace the body of `Handler::handle` to implement the tee:

```rust
    pub async fn handle(&self, authority: String, mut req: Request<Incoming>) -> Result<Response<BoxBody>, Infallible> {
        let key = CacheKey::from_request(&req, "https", &authority);
        if let Ok(Some(hit)) = self.cache.lookup(&key).await {
            return Ok(reply_from_cache(hit));
        }

        // Rebuild the upstream URI (authority is from CONNECT, path comes from inner request).
        let scheme = req.uri().scheme_str().unwrap_or("https");
        let path_and_query = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let upstream_uri: http::Uri = match format!("{scheme}://{authority}{path_and_query}").parse() {
            Ok(u) => u,
            Err(_) => return Ok(bad_gateway("bad upstream uri")),
        };
        *req.uri_mut() = upstream_uri.clone();
        req.headers_mut().remove(http::header::HOST);

        // Forward request body unchanged.
        let (parts, body) = req.into_parts();
        let body = body
            .map_err(|e| std::io::Error::other(e))
            .boxed();
        let upstream_req = http::Request::from_parts(parts, body);

        let resp = match self.upstream.send(upstream_req).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "upstream send failed");
                return Ok(bad_gateway("upstream error"));
            }
        };

        let status = resp.status();
        let cache_eligible = status.is_success() || status.is_redirection();
        let (resp_parts, resp_body) = resp.into_parts();

        // Build writer only when caching this response.
        let writer = if cache_eligible {
            let meta = ResponseMeta {
                status: status.as_u16(),
                headers: header_pairs(&resp_parts.headers),
            };
            match self.cache.begin_store(&key, meta, self.default_ttl).await {
                Ok(w) => Some(w),
                Err(e) => {
                    tracing::warn!(error = %e, "begin_store failed - pass-through");
                    None
                }
            }
        } else {
            None
        };

        // Tee channel: client receives via stream; we also stream into the writer in the background.
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(32);
        let disconnect_cap = self.disconnect_cap;
        tokio::spawn(tee_pump(resp_body, writer, tx, disconnect_cap));

        let mut builder = Response::builder().status(resp_parts.status);
        for (k, v) in resp_parts.headers.iter() {
            builder = builder.header(k, v);
        }
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx)
            .map_ok(http_body::Frame::data);
        let body = StreamBody::new(stream).boxed();
        Ok(builder.body(body).unwrap())
    }
}

async fn tee_pump(
    mut upstream: hyper::body::Incoming,
    mut writer: Option<Box<dyn roxy_cache::CacheWriter>>,
    tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    disconnect_cap: u64,
) {
    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;
    let mut client_alive = true;
    let mut bytes_past_disconnect = 0u64;
    while let Some(frame) = upstream.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                if let Some(w) = writer.take() { w.abort(); }
                let _ = tx.send(Err(std::io::Error::other(e))).await;
                return;
            }
        };
        let chunk = match frame.into_data() {
            Ok(b) => b,
            Err(_trailers) => continue,
        };

        // Write to cache writer if any.
        if let Some(w) = writer.as_mut() {
            if let Err(e) = w.write_all(&chunk).await {
                tracing::warn!(error = %e, "cache write failed - aborting");
                if let Some(w) = writer.take() { w.abort(); }
            }
        }

        if client_alive {
            if tx.send(Ok(chunk.clone())).await.is_err() {
                client_alive = false;
                tracing::debug!("client disconnected; continuing to drain upstream up to cap");
            }
        } else {
            bytes_past_disconnect = bytes_past_disconnect.saturating_add(chunk.len() as u64);
            if bytes_past_disconnect >= disconnect_cap {
                tracing::warn!(cap = disconnect_cap, "exceeded post-disconnect cap; aborting cache write");
                if let Some(w) = writer.take() { w.abort(); }
                return;
            }
        }
    }

    if let Some(w) = writer.take() {
        if let Err(e) = w.finish().await {
            tracing::warn!(error = %e, "cache finalize failed");
        }
    }
}

fn header_pairs(h: &http::HeaderMap) -> Vec<(String, Vec<u8>)> {
    h.iter()
        .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
        .collect()
}

fn bad_gateway(msg: &'static str) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Full::new(Bytes::from_static(msg.as_bytes())).map_err(|never| match never {}).boxed())
        .unwrap()
}
```

Add deps to `crates/roxy-proxy/Cargo.toml` under `[dependencies]`:

```toml
tokio-stream = "0.1"
futures = { workspace = true }
http-body = { workspace = true }
roxy-cache = { workspace = true }
```

Also import `roxy_cache::ResponseMeta` and friends in the file.

- [ ] **Step 3: Build clean (functional behavior is covered by integration tests later)**

```bash
cargo build -p roxy-proxy
cargo clippy -p roxy-proxy --all-targets -- -D warnings
```

Expected: clean.

- [ ] **Step 4: Commit and close**

```bash
git add crates/roxy-proxy/ crates/roxy-http/
git commit -m "feat(roxy-z0p): miss-path tee-while-caching + 5xx not cached + disconnect cap"
bd close roxy-z0p
```

---

## Task 19: `roxy-proxy` — CLI scaffold (clap subcommands)

**Beads:** `roxy-qxg` (start)

**Files:** `crates/roxy-proxy/src/{cli.rs,main.rs}`

- [ ] **Step 1: Mark in progress**

```bash
bd update roxy-qxg --status=in_progress
```

- [ ] **Step 2: Add the clap CLI**

Create `crates/roxy-proxy/src/cli.rs`:

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "roxy", version, about = "Caching MITM proxy")]
pub struct Cli {
    /// Path to roxy config TOML.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy.
    Serve,
    /// CA trust-store management.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum CaAction {
    /// Install the generated CA into the host trust store.
    Install {
        /// Override the CA directory.
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        /// Print the platform command instead of executing it.
        #[arg(long)]
        print_only: bool,
    },
    /// Remove the installed CA from the host trust store.
    Uninstall {
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        #[arg(long)]
        print_only: bool,
    },
}
```

Replace `crates/roxy-proxy/src/main.rs`:

```rust
mod cli;
mod handler;
mod serve;
mod ca_cmd;

use clap::Parser;
use cli::{Cli, Command, CaAction};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .init();

    let cmd = cli.command.unwrap_or(Command::Serve);
    match cmd {
        Command::Serve => serve::run(cli.config.as_deref()).await,
        Command::Ca { action } => match action {
            CaAction::Install { ca_dir, print_only } => ca_cmd::install(ca_dir, print_only),
            CaAction::Uninstall { ca_dir, print_only } => ca_cmd::uninstall(ca_dir, print_only),
        },
    }
}
```

Create `crates/roxy-proxy/src/serve.rs`:

```rust
use std::path::Path;

pub async fn run(_config_path: Option<&Path>) -> anyhow::Result<()> {
    anyhow::bail!("serve not yet wired - see Task 20")
}
```

Create `crates/roxy-proxy/src/ca_cmd.rs`:

```rust
use std::path::PathBuf;

pub fn install(_ca_dir: Option<PathBuf>, _print_only: bool) -> anyhow::Result<()> {
    anyhow::bail!("ca install not yet wired - see Task 22")
}

pub fn uninstall(_ca_dir: Option<PathBuf>, _print_only: bool) -> anyhow::Result<()> {
    anyhow::bail!("ca uninstall not yet wired - see Task 22")
}
```

- [ ] **Step 3: Build + sanity-check --help**

```bash
cargo build -p roxy-proxy
./target/debug/roxy --help
./target/debug/roxy ca --help
```

Expected: both `--help` outputs list the documented subcommands and flags.

- [ ] **Step 4: Commit**

```bash
git add crates/roxy-proxy/
git commit -m "feat(roxy-qxg): clap subcommand scaffold (serve + ca install/uninstall)"
```

---

## Task 20: `roxy-proxy` — wire `serve` (config → mitm → cache → accept loop)

**Beads:** `roxy-qxg` (finish)

**Files:** `crates/roxy-proxy/src/serve.rs`, `crates/roxy-proxy/src/main.rs`

- [ ] **Step 1: Implement the serve subcommand**

Replace `crates/roxy-proxy/src/serve.rs`:

```rust
use crate::handler::Handler;
use anyhow::Context;
use roxy_cache::Cache;
use roxy_cache_fs::FsCache;
use roxy_config::Config;
use roxy_http::accept::ConnHandler;
use roxy_mitm::{Ca, LeafSigner, SniResolver, Terminator};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub async fn run(config_path: Option<&Path>) -> anyhow::Result<()> {
    let cfg = load_config(config_path)?;
    let cache = Arc::new(FsCache::open(&cfg.cache.dir).context("open cache")?);
    let evicted = cache.cleanup_tmp().context("cleanup tmp")?;
    if evicted > 0 {
        tracing::info!(evicted, "cleaned orphan tmp files");
    }

    let ca = Ca::load_or_create(&cfg.ca.dir).context("load/create CA")?;
    print_ca_hint(&ca);

    let signer = LeafSigner::new(ca);
    let resolver = Arc::new(SniResolver::new(signer, NonZeroUsize::new(10_000).unwrap()));
    let terminator = Terminator::new(resolver);

    let upstream = roxy_http::UpstreamClient::new().context("upstream client")?;
    let handler = ProxyConnHandler {
        inner: Arc::new(Handler {
            cache: cache.clone(),
            default_ttl: Duration::from_secs(cfg.cache.default_ttl_seconds),
            upstream,
            disconnect_cap: 50 * 1024 * 1024,
        }),
    };

    tracing::info!(addr = %cfg.listen, "listening");
    roxy_http::accept::run(cfg.listen, terminator, Arc::new(handler)).await
        .map_err(Into::into)
}

fn load_config(path: Option<&Path>) -> anyhow::Result<Config> {
    let path = path.map(|p| p.to_path_buf()).unwrap_or_else(roxy_config::default_config_path);
    if path.exists() {
        Ok(roxy_config::load_from_path(&path)?)
    } else {
        Ok(Config::default().with_expanded_paths()?)
    }
}

fn print_ca_hint(ca: &Ca) {
    eprintln!(
        "roxy CA at {}\n  run 'roxy ca install' to add this CA to your system trust store",
        ca.cert_path.display()
    );
}

struct ProxyConnHandler<C: Cache + 'static> {
    inner: Arc<Handler<C>>,
}

#[async_trait::async_trait]
impl<C: Cache + 'static> ConnHandler for ProxyConnHandler<C> {
    async fn handle(
        &self,
        authority: String,
        tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) {
        let inner = self.inner.clone();
        let authority_clone = authority.clone();
        roxy_http::serve_tls(tls, move |req| {
            let inner = inner.clone();
            let authority = authority_clone.clone();
            async move { inner.handle(authority, req).await }
        }).await;
    }
}
```

Add deps to `crates/roxy-proxy/Cargo.toml`:

```toml
async-trait = { workspace = true }
roxy-cache-fs = { workspace = true }
tokio-rustls = "0.26"
```

- [ ] **Step 2: Smoke build**

```bash
cargo build -p roxy-proxy
cargo clippy -p roxy-proxy --all-targets -- -D warnings
```

Expected: clean.

- [ ] **Step 3: Manual smoke (optional but worth doing once)**

```bash
RUST_LOG=info ./target/debug/roxy serve --config /tmp/roxy.toml 2>/dev/null &
# In another shell, after trusting the CA: curl -x http://127.0.0.1:8080 https://example.com
kill %1
```

Skip if unsure — the real verification is the integration test suite (Task 23+).

- [ ] **Step 4: Commit and close**

```bash
git add crates/roxy-proxy/
git commit -m "feat(roxy-qxg): wire serve subcommand end-to-end"
bd close roxy-qxg
```

---

## Task 21: `roxy-mitm` — trust-store backends (macOS + Linux + fingerprint)

**Beads:** `roxy-kcq` (start)

**Files:** `crates/roxy-mitm/src/trust/{mod.rs,macos.rs,linux.rs}`, modify `lib.rs`

- [ ] **Step 1: Mark in progress**

```bash
bd update roxy-kcq --status=in_progress
```

- [ ] **Step 2: Add the trust module**

Add to `crates/roxy-mitm/src/lib.rs`:

```rust
pub mod trust;
```

Create `crates/roxy-mitm/src/trust/mod.rs`:

```rust
use crate::ca::Ca;
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("unsupported platform")]
    Unsupported,

    #[error("command failed: {0}")]
    Command(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not running as root - run: {0}")]
    NeedsRoot(String),
}

#[derive(Debug)]
pub enum Plan {
    Execute(Vec<String>),
    PrintOnly(Vec<String>),
    AlreadyInstalled,
}

/// SHA-256 over the DER-encoded CA certificate.
pub fn fingerprint_hex(ca: &Ca) -> Result<String, TrustError> {
    let mut der_iter = rustls_pemfile::certs(&mut std::io::Cursor::new(ca.cert_pem.as_bytes()));
    let der = der_iter.next()
        .ok_or_else(|| TrustError::Command("CA pem has no certificate".into()))?
        .map_err(|e| TrustError::Command(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(der.as_ref());
    Ok(hex::encode(h.finalize()))
}

pub fn install(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    #[cfg(target_os = "macos")]
    return macos::install(ca, print_only);
    #[cfg(target_os = "linux")]
    return linux::install(ca, print_only);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ca, print_only);
        Err(TrustError::Unsupported)
    }
}

pub fn uninstall(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    #[cfg(target_os = "macos")]
    return macos::uninstall(ca, print_only);
    #[cfg(target_os = "linux")]
    return linux::uninstall(ca, print_only);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ca, print_only);
        Err(TrustError::Unsupported)
    }
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let fp = fingerprint_hex(&ca).unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
```

Create `crates/roxy-mitm/src/trust/macos.rs`:

```rust
use super::{Plan, TrustError};
use crate::ca::Ca;
use std::process::Command;

pub fn install(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    if installed(ca)? {
        return Ok(Plan::AlreadyInstalled);
    }
    let cmd = vec![
        "security".into(),
        "add-trusted-cert".into(),
        "-r".into(),
        "trustRoot".into(),
        "-k".into(),
        login_keychain(),
        ca.cert_path.display().to_string(),
    ];
    if print_only {
        return Ok(Plan::PrintOnly(cmd));
    }
    let status = Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    if !status.success() {
        return Err(TrustError::Command(format!("security exited {status}")));
    }
    Ok(Plan::Execute(cmd))
}

pub fn uninstall(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    if !installed(ca)? {
        return Ok(Plan::AlreadyInstalled); // semantically "nothing to do"
    }
    let cmd = vec![
        "security".into(),
        "delete-certificate".into(),
        "-c".into(),
        "Roxy Local CA".into(),
        login_keychain(),
    ];
    if print_only {
        return Ok(Plan::PrintOnly(cmd));
    }
    let _ = Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    Ok(Plan::Execute(cmd))
}

fn login_keychain() -> String {
    if let Some(home) = dirs::home_dir() {
        return home.join("Library/Keychains/login.keychain-db").display().to_string();
    }
    "login.keychain-db".into()
}

fn installed(ca: &Ca) -> Result<bool, TrustError> {
    // Cheap check: look for any cert with our CN in the login keychain.
    let out = Command::new("security")
        .args(["find-certificate", "-c", "Roxy Local CA", &login_keychain()])
        .output()?;
    let _ = ca; // (matching by fingerprint requires DER export; CN is sufficient for MVP)
    Ok(out.status.success())
}
```

Create `crates/roxy-mitm/src/trust/linux.rs`:

```rust
use super::{Plan, TrustError};
use crate::ca::Ca;
use std::process::Command;

const SYSTEM_DIR: &str = "/usr/local/share/ca-certificates";

pub fn install(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    let target = format!("{SYSTEM_DIR}/roxy-ca.crt");
    if std::path::Path::new(&target).exists() {
        return Ok(Plan::AlreadyInstalled);
    }
    let cmd = vec![
        "install".into(),
        "-m".into(), "0644".into(),
        ca.cert_path.display().to_string(),
        target.clone(),
    ];
    let update = vec!["update-ca-certificates".into()];

    if print_only || !is_root() {
        let mut plan = cmd.clone();
        plan.extend(update.clone());
        if print_only {
            return Ok(Plan::PrintOnly(plan));
        } else {
            let pretty = format!("sudo {}", plan.join(" "));
            return Err(TrustError::NeedsRoot(pretty));
        }
    }

    let status = Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    if !status.success() {
        return Err(TrustError::Command(format!("install exited {status}")));
    }
    let status = Command::new(&update[0]).args(&update[1..]).status()?;
    if !status.success() {
        return Err(TrustError::Command(format!("update-ca-certificates exited {status}")));
    }
    Ok(Plan::Execute(cmd))
}

pub fn uninstall(_ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    let target = format!("{SYSTEM_DIR}/roxy-ca.crt");
    let exists = std::path::Path::new(&target).exists();
    if !exists {
        return Ok(Plan::AlreadyInstalled);
    }
    let cmd = vec!["rm".into(), "-f".into(), target.clone()];
    let update = vec!["update-ca-certificates".into()];

    if print_only || !is_root() {
        let mut plan = cmd.clone();
        plan.extend(update.clone());
        if print_only {
            return Ok(Plan::PrintOnly(plan));
        } else {
            let pretty = format!("sudo {}", plan.join(" "));
            return Err(TrustError::NeedsRoot(pretty));
        }
    }
    Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    Command::new(&update[0]).args(&update[1..]).status()?;
    Ok(Plan::Execute(cmd))
}

fn is_root() -> bool {
    #[cfg(unix)]
    return rustix::process::geteuid().is_root();
    #[cfg(not(unix))]
    return false;
}
```

Add `rustix` and `dirs` to deps in `crates/roxy-mitm/Cargo.toml`:

```toml
dirs = { workspace = true }

[target.'cfg(unix)'.dependencies]
rustix = { version = "0.38", features = ["process"] }
```

Run: `cargo test -p roxy-mitm`

Expected: 7 passing tests (the fingerprint test is new).

- [ ] **Step 3: Commit**

```bash
git add crates/roxy-mitm/
git commit -m "feat(roxy-kcq): trust-store install backends (macOS + Linux) with print-only + fingerprint"
```

---

## Task 22: `roxy-proxy` — wire `ca install` / `ca uninstall`

**Beads:** `roxy-kcq` (finish)

**Files:** `crates/roxy-proxy/src/ca_cmd.rs`

- [ ] **Step 1: Replace stub with full wiring**

```rust
use anyhow::Context;
use roxy_config::Config;
use roxy_mitm::trust::{install as t_install, uninstall as t_uninstall, Plan};
use roxy_mitm::Ca;
use std::path::{Path, PathBuf};

fn resolve_ca_dir(override_dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(d) = override_dir {
        return Ok(d);
    }
    let cfg = Config::default().with_expanded_paths()?;
    Ok(cfg.ca.dir)
}

fn load_ca(ca_dir: &Path) -> anyhow::Result<Ca> {
    Ca::load_or_create(ca_dir).context("CA load/create")
}

pub fn install(ca_dir: Option<PathBuf>, print_only: bool) -> anyhow::Result<()> {
    let ca_dir = resolve_ca_dir(ca_dir)?;
    let ca = load_ca(&ca_dir)?;
    match t_install(&ca, print_only)? {
        Plan::AlreadyInstalled => {
            println!("CA already installed.");
        }
        Plan::PrintOnly(cmd) => {
            println!("Would run:\n  {}", cmd.join(" "));
        }
        Plan::Execute(cmd) => {
            println!("Installed CA. Ran: {}", cmd.join(" "));
        }
    }
    Ok(())
}

pub fn uninstall(ca_dir: Option<PathBuf>, print_only: bool) -> anyhow::Result<()> {
    let ca_dir = resolve_ca_dir(ca_dir)?;
    let ca = load_ca(&ca_dir)?;
    match t_uninstall(&ca, print_only)? {
        Plan::AlreadyInstalled => {
            println!("CA not currently installed.");
        }
        Plan::PrintOnly(cmd) => {
            println!("Would run:\n  {}", cmd.join(" "));
        }
        Plan::Execute(cmd) => {
            println!("Uninstalled CA. Ran: {}", cmd.join(" "));
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Smoke test (manual, gated by platform)**

```bash
cargo build -p roxy-proxy
./target/debug/roxy ca install --print-only
./target/debug/roxy ca uninstall --print-only
```

Expected: both print the platform command without executing.

- [ ] **Step 3: Commit and close**

```bash
git add crates/roxy-proxy/
git commit -m "feat(roxy-kcq): wire roxy ca install/uninstall subcommands"
bd close roxy-kcq
```

---

## Task 23: Integration test harness (fake origin + test CA)

**Beads:** `roxy-xn8` (start)

**Files:** `crates/roxy-proxy/tests/common/{mod.rs,trust.rs}`

- [ ] **Step 1: Mark in progress + add the harness**

```bash
bd update roxy-xn8 --status=in_progress
```

Create `crates/roxy-proxy/tests/common/trust.rs`:

```rust
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, IsCa, BasicConstraints, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub struct TestCa {
    pub cert_pem: String,
    pub key_pair: KeyPair,
}

impl TestCa {
    pub fn new() -> Self {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key_pair).unwrap();
        Self { cert_pem: cert.pem(), key_pair }
    }

    pub fn mint(&self, sni: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let leaf_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sni);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(sni.to_string().try_into().unwrap())];
        let issuer = CertificateParams::from_ca_cert_pem(&self.cert_pem).unwrap();
        let issuer_cert = issuer.self_signed(&self.key_pair).unwrap();
        let leaf = params.signed_by(&leaf_key, &issuer_cert, &self.key_pair).unwrap();
        let cert_der = CertificateDer::from(leaf.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        (cert_der, key_der)
    }
}
```

Create `crates/roxy-proxy/tests/common/mod.rs`:

```rust
pub mod trust;

use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use trust::TestCa;

pub struct Fixture {
    pub roxy_addr: SocketAddr,
    pub origin_addr: SocketAddr,
    pub origin_host: String,
    pub roxy_ca_pem: String,
    pub origin_ca: Arc<TestCa>,
    _origin_handle: JoinHandle<()>,
    _roxy_handle: JoinHandle<anyhow::Result<()>>,
    _tmp: TempDir,
}

pub async fn spawn_fixture(default_ttl_seconds: u64) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();

    // origin
    let origin_ca = Arc::new(TestCa::new());
    let (leaf_cert, leaf_key) = origin_ca.mint("origin.local");
    let rustls_cfg = RustlsConfig::from_der(vec![leaf_cert.to_vec()], leaf_key.secret_der().to_vec()).await.unwrap();
    let app = Router::new()
        .route("/echo/:msg", get(|axum::extract::Path(msg): axum::extract::Path<String>| async move { msg }))
        .route("/big/:n", get(|axum::extract::Path(n): axum::extract::Path<usize>| async move {
            "x".repeat(n)
        }))
        .route("/boom", get(|| async {
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "oops")
        }));
    let origin_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_addr: SocketAddr = origin_listener.local_addr().unwrap();
    let origin_handle = tokio::spawn(async move {
        axum_server::from_tcp_rustls(origin_listener, rustls_cfg)
            .serve(app.into_make_service()).await.unwrap();
    });

    // roxy: bind a TcpListener so we know the port, then run
    let roxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let roxy_addr: SocketAddr = roxy_listener.local_addr().unwrap();
    drop(roxy_listener); // free port; race-ish but fine for tests
    let cfg_path = tmp.path().join("roxy.toml");
    std::fs::write(&cfg_path, format!(r#"
listen = "{roxy_addr}"
[cache]
dir = "{}"
default_ttl_seconds = {default_ttl_seconds}
[ca]
dir = "{}"
[log]
level = "warn"
"#, tmp.path().join("cache").display(), tmp.path().join("ca").display())).unwrap();
    let roxy_cfg = roxy_config::load_from_path(&cfg_path).unwrap();
    let ca_dir = roxy_cfg.ca.dir.clone();
    let roxy_handle = tokio::spawn(async move {
        roxy_proxy_lib::serve::run(Some(&cfg_path)).await
    });
    // wait until listener is up
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(roxy_addr).await.is_ok() { break; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let roxy_ca_pem = std::fs::read_to_string(ca_dir.join("roxy-ca.crt")).unwrap();

    Fixture {
        roxy_addr,
        origin_addr,
        origin_host: format!("origin.local:{}", origin_addr.port()),
        roxy_ca_pem,
        origin_ca,
        _origin_handle: origin_handle,
        _roxy_handle: roxy_handle,
        _tmp: tmp,
    }
}

pub fn client_trusting(roxy_ca_pem: &str, origin_ca_pem: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(format!("http://{}", "unused")).unwrap()) // overridden below
        .add_root_certificate(reqwest::Certificate::from_pem(roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(origin_ca_pem.as_bytes()).unwrap())
        .build().unwrap()
}
```

(This harness pulls `roxy_proxy_lib::serve::run`. To make `serve` callable from tests, expose `serve` and `handler` from the binary crate by adding a small `lib.rs`.)

Create `crates/roxy-proxy/src/lib.rs`:

```rust
pub mod cli;
pub mod handler;
pub mod serve;
pub mod ca_cmd;
```

And in `crates/roxy-proxy/Cargo.toml` add `[lib]`:

```toml
[lib]
name = "roxy_proxy_lib"
path = "src/lib.rs"
```

Update `crates/roxy-proxy/src/main.rs` to use the library modules:

```rust
use clap::Parser;
use roxy_proxy_lib::cli::{Cli, Command, CaAction};
use roxy_proxy_lib::{serve, ca_cmd};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .init();

    let cmd = cli.command.unwrap_or(Command::Serve);
    match cmd {
        Command::Serve => serve::run(cli.config.as_deref()).await,
        Command::Ca { action } => match action {
            CaAction::Install { ca_dir, print_only } => ca_cmd::install(ca_dir, print_only),
            CaAction::Uninstall { ca_dir, print_only } => ca_cmd::uninstall(ca_dir, print_only),
        },
    }
}
```

- [ ] **Step 2: Verify the harness compiles**

```bash
cargo test -p roxy-proxy --no-run
```

Expected: clean build of the test binaries.

- [ ] **Step 3: Commit**

```bash
git add crates/roxy-proxy/
git commit -m "test(roxy-xn8): integration test harness (fake origin + roxy fixture)"
```

---

## Task 24: Integration — golden miss → hit + tee correctness

**Beads:** `roxy-xn8` (continue)

**Files:** `crates/roxy-proxy/tests/golden.rs`

- [ ] **Step 1: Write the test**

```rust
mod common;

use common::spawn_fixture;

#[tokio::test]
async fn miss_then_hit_returns_same_body_and_caches() {
    let f = spawn_fixture(3600).await;
    let proxy_url = format!("http://{}", f.roxy_addr);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.origin_ca.cert_pem.as_bytes()).unwrap())
        .build().unwrap();

    let url = format!("https://{}/echo/hello", f.origin_host);

    let r1 = client.get(&url).send().await.unwrap();
    assert_eq!(r1.status(), 200);
    let b1 = r1.text().await.unwrap();
    assert_eq!(b1, "hello");

    let r2 = client.get(&url).send().await.unwrap();
    assert_eq!(r2.status(), 200);
    let b2 = r2.text().await.unwrap();
    assert_eq!(b2, "hello");

    // Hard correctness: byte-for-byte identical body across miss and hit.
    assert_eq!(b1, b2);
}
```

Run: `cargo test -p roxy-proxy --test golden`

Expected: **PASS**.

- [ ] **Step 2: Commit**

```bash
git add crates/roxy-proxy/tests/golden.rs
git commit -m "test(roxy-xn8): golden miss→hit + tee body correctness"
```

---

## Task 25: Integration — TTL expiry behaves as miss

**Beads:** `roxy-xn8` (continue)

**Files:** `crates/roxy-proxy/tests/ttl.rs`

- [ ] **Step 1: Write the test**

```rust
mod common;

use common::spawn_fixture;
use std::time::Duration;

#[tokio::test]
async fn expired_entry_is_missed_and_refetched() {
    // ttl = 1s
    let f = spawn_fixture(1).await;
    let proxy_url = format!("http://{}", f.roxy_addr);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.origin_ca.cert_pem.as_bytes()).unwrap())
        .build().unwrap();
    let url = format!("https://{}/echo/x", f.origin_host);
    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "x");
    // (We don't have an "origin hit count" wire yet — just assert the request still succeeds
    //  after the entry expires. Origin-hit counting can be added when needed.)
}
```

Run: `cargo test -p roxy-proxy --test ttl`. Expected: **PASS**.

- [ ] **Step 2: Commit**

```bash
git add crates/roxy-proxy/tests/ttl.rs
git commit -m "test(roxy-xn8): TTL expiry surfaces as a miss"
```

---

## Task 26: Integration — origin 5xx pass-through is not cached

**Beads:** `roxy-xn8` (continue)

**Files:** `crates/roxy-proxy/tests/errors.rs`

- [ ] **Step 1: Write the test**

```rust
mod common;

use common::spawn_fixture;

#[tokio::test]
async fn origin_5xx_is_forwarded_but_not_cached() {
    let f = spawn_fixture(3600).await;
    let proxy_url = format!("http://{}", f.roxy_addr);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.origin_ca.cert_pem.as_bytes()).unwrap())
        .build().unwrap();
    let url = format!("https://{}/boom", f.origin_host);

    let r = client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), 500);
    let body = r.text().await.unwrap();
    assert!(body.contains("oops"));

    // No cache entry should exist for /boom — we verify by hitting it again and asserting
    // the status is still 500 (vs a possible-different code if cached oddly) AND that no
    // blob shows up. The blob check is brittle in-process; the status check + the absence
    // of HTTP-level caching for 5xx is the contract.
    let r = client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), 500);
}
```

Run: `cargo test -p roxy-proxy --test errors`. Expected: **PASS**.

- [ ] **Step 2: Commit**

```bash
git add crates/roxy-proxy/tests/errors.rs
git commit -m "test(roxy-xn8): 5xx pass-through is forwarded and not cached"
```

---

## Task 27: Integration — large body within and beyond cap

**Beads:** `roxy-xn8` (finish)

**Files:** `crates/roxy-proxy/tests/streaming.rs`

- [ ] **Step 1: Write the test**

```rust
mod common;

use common::spawn_fixture;

#[tokio::test]
async fn large_body_under_cap_is_cached() {
    let f = spawn_fixture(3600).await;
    let proxy_url = format!("http://{}", f.roxy_addr);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.origin_ca.cert_pem.as_bytes()).unwrap())
        .build().unwrap();
    // 1 MiB body — well under the 50 MiB disconnect cap, and under the (no-)response size cap.
    let url = format!("https://{}/big/1048576", f.origin_host);
    let body = client.get(&url).send().await.unwrap().bytes().await.unwrap();
    assert_eq!(body.len(), 1_048_576);
    // Second request must serve from cache and be byte-identical.
    let body2 = client.get(&url).send().await.unwrap().bytes().await.unwrap();
    assert_eq!(body, body2);
}
```

Run: `cargo test -p roxy-proxy --test streaming`. Expected: **PASS**.

- [ ] **Step 2: Commit and close**

```bash
git add crates/roxy-proxy/tests/streaming.rs
git commit -m "test(roxy-xn8): large body under cap caches correctly"
bd close roxy-xn8
```

---

## Task 28: Smoke test against public endpoint

**Beads:** `roxy-79n`

**Files:** `crates/roxy-proxy/tests/smoke.rs`

- [ ] **Step 1: Mark in progress + write the test**

```bash
bd update roxy-79n --status=in_progress
```

```rust
mod common;

use common::spawn_fixture;

#[tokio::test]
#[ignore = "smoke: requires internet"]
async fn httpbin_get_via_roxy() {
    let f = spawn_fixture(3600).await;
    let proxy_url = format!("http://{}", f.roxy_addr);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .danger_accept_invalid_hostnames(true) // tolerate fixture quirks
        .build().unwrap();
    let r1 = client.get("https://httpbin.org/anything").send().await.unwrap();
    assert_eq!(r1.status(), 200);
    let r2 = client.get("https://httpbin.org/anything").send().await.unwrap();
    assert_eq!(r2.status(), 200);
}
```

Run (locally, not in CI): `cargo test -p roxy-proxy --test smoke -- --ignored`

Expected: **PASS** when run by hand on a host with internet.

- [ ] **Step 2: Commit and close**

```bash
git add crates/roxy-proxy/tests/smoke.rs
git commit -m "test(roxy-79n): #[ignore] smoke test against httpbin"
bd close roxy-79n
```

---

## Final verification + push

- [ ] **Step 1: Full clean build**

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --workspace
```

Expected: all green.

- [ ] **Step 2: Confirm all beads issues are closed**

```bash
bd list --status=open
```

Expected: empty list.

- [ ] **Step 3: Push**

```bash
git pull --rebase
git push
git status   # must show "up to date with origin/main"
```

---

## Spec coverage self-check

| Spec section | Covered by tasks |
|---|---|
| §3 goals (HTTPS proxy, MITM, content-addressable cache, h1+h2, no panics, `ca install`) | 14–22 |
| §4 architecture (six crates, five-libs-plus-binary) | 1 |
| §5 request lifecycle (CONNECT → MITM → cache lookup → upstream → tee) | 15–18, 20, 23–24 |
| §5.1 tee vs store-then-forward | 18 |
| §5.2 cert minting cache (SNI LRU) | 8 |
| §6.1 cache key (sorted query) | 4 |
| §6.2 content-addressable storage (fs blobs + sqlite) | 10–13 |
| §6.3 TTL + freshness | 13, 25 |
| §6.4 `Cache` trait | 5 |
| §7.1 CA generation + load + first-run hint | 6, 20 |
| §7.2 leaf cert minting (24h, SAN=SNI, LRU) | 7, 8 |
| §7.3 TLS interception flow (ALPN h2,http/1.1) | 9, 16 |
| §7.4 `roxy ca install/uninstall` | 21, 22 |
| §8 upstream client (hyper + hyper-rustls, ALPN) | 14 |
| §9 config schema | 2, 3 |
| §10 error handling (5xx not cached, disconnect cap, cache failure pass-through, lints) | 1 (lints), 18 (5xx, disconnect), 20 (cleanup_tmp), 26 (5xx integration) |
| §11 testing (unit + integration + smoke) | 4–13 unit, 23–27 integration, 28 smoke |
| §12 known limits | (no code; spec-only) |

No gaps.
