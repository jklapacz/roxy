#![allow(clippy::unwrap_used)]
#![allow(dead_code)]

pub mod fake_proxy;
pub mod trust;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::PrivateKeyDer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use trust::TestCa;

#[derive(Default, Clone)]
pub struct HitCounter {
    inner: Arc<Mutex<HashMap<String, usize>>>,
}

impl HitCounter {
    pub fn bump(&self, key: &str) {
        if let Ok(mut g) = self.inner.lock() {
            *g.entry(key.to_string()).or_insert(0) += 1;
        }
    }

    pub fn count(&self, key: &str) -> usize {
        self.inner
            .lock()
            .map(|g| g.get(key).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

#[derive(Clone)]
struct OriginState {
    hits: HitCounter,
}

pub struct Fixture {
    pub roxy_addr: SocketAddr,
    pub origin_addr: SocketAddr,
    pub origin_host: String,
    pub roxy_ca_pem: String,
    pub origin_ca: Arc<TestCa>,
    pub hits: HitCounter,
    /// roxy's cache directory. With caching disabled it must stay free of
    /// cache entries — see `cache_dir_is_empty`.
    pub cache_dir: PathBuf,
    _origin_handle: JoinHandle<()>,
    _roxy_handle: JoinHandle<anyhow::Result<()>>,
    _tmp: TempDir,
}

impl Fixture {
    /// Build a URL pointing at the fake origin (HTTPS, localhost).
    pub fn fake_origin_url(&self, path: &str) -> String {
        format!("https://{}{}", self.origin_host, path)
    }

    /// Build a URL pointing at the fake origin's `/status/:code` route, which
    /// returns the requested status code with a small body.
    pub fn fake_origin_url_status(&self, status: u16, path: &str) -> String {
        let suffix = if path.is_empty() { "" } else { path };
        format!(
            "https://{}/status/{}?p={}",
            self.origin_host,
            status,
            urlencoding_minimal(suffix)
        )
    }

    pub fn upstream_hit_count(&self, key: &str) -> usize {
        self.hits.count(key)
    }

    /// True when roxy's cache directory holds no cache entries. `FsCache::open`
    /// always creates the `index.sqlite` index (plus its `-wal`/`-shm`
    /// sidecars), so those structural files are ignored — any *other* file (a
    /// stored blob, a tmp write) means a cache operation actually occurred.
    pub fn cache_dir_is_empty(&self) -> bool {
        fn entry_files(dir: &std::path::Path) -> usize {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return 0;
            };
            let mut n = 0;
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    n += entry_files(&path);
                } else if !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("index.sqlite")
                {
                    n += 1;
                }
            }
            n
        }
        entry_files(&self.cache_dir) == 0
    }
}

/// Encode a path so it can be used as a query parameter. Tests use this only
/// for tracking — we strip leading `/` and percent-escape just enough to
/// survive a query value.
fn urlencoding_minimal(s: &str) -> String {
    let trimmed = s.trim_start_matches('/');
    let mut out = String::with_capacity(trimmed.len());
    for b in trimmed.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub struct FixtureBuilder {
    default_ttl_seconds: u64,
    default_profile: Option<String>,
    profiles_dir: Option<PathBuf>,
    inject_origin_ca_into_wreq: bool,
    cache_enabled: bool,
    upstream_proxy: Option<String>,
}

impl FixtureBuilder {
    pub fn new() -> Self {
        Self {
            default_ttl_seconds: 3600,
            default_profile: None,
            profiles_dir: None,
            inject_origin_ca_into_wreq: false,
            cache_enabled: true,
            upstream_proxy: None,
        }
    }

    pub fn default_ttl_seconds(mut self, v: u64) -> Self {
        self.default_ttl_seconds = v;
        self
    }

    /// Set `[cache] enabled`. When false, roxy still MITMs and proxies every
    /// request but never serves from or writes to the cache.
    pub fn cache_enabled(mut self, v: bool) -> Self {
        self.cache_enabled = v;
        self
    }

    /// Configure roxy's `[upstream] proxy`. The value is written verbatim into
    /// the generated roxy.toml.
    pub fn upstream_proxy(mut self, url: impl Into<String>) -> Self {
        self.upstream_proxy = Some(url.into());
        self
    }

    pub fn default_profile(mut self, name: impl Into<String>) -> Self {
        self.default_profile = Some(name.into());
        self
    }

    pub fn profiles_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.profiles_dir = Some(dir.into());
        self
    }

    /// Inject the fake origin's CA into the wreq impersonate client's trust
    /// store. Required for tests that drive the wreq path end-to-end against
    /// the in-process fake origin (whose leaf cert is signed by a private
    /// test CA that wreq does NOT trust by default).
    pub fn inject_origin_ca_into_wreq(mut self) -> Self {
        self.inject_origin_ca_into_wreq = true;
        self
    }

    pub async fn build(self) -> Fixture {
        spawn_fixture_with(self).await
    }
}

pub async fn spawn_fixture(default_ttl_seconds: u64) -> Fixture {
    FixtureBuilder::new()
        .default_ttl_seconds(default_ttl_seconds)
        .build()
        .await
}

/// Serializes fixture startup across `#[tokio::test]`s in the same binary.
/// Several fixtures mutate process-global env vars (`SSL_CERT_FILE`,
/// `ROXY_TEST_EXTRA_ROOT_PEM_PATH`) before spawning the roxy task; running
/// them concurrently would race. We hold the lock from the start of fixture
/// setup until the roxy task has had a chance to read the env vars (which
/// happens during `serve::run`'s synchronous prelude). Releasing after the
/// listener is up is correct because the env vars are read once, at
/// startup, by `build_impersonate`.
static FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn spawn_fixture_with(b: FixtureBuilder) -> Fixture {
    let _guard = FIXTURE_LOCK.lock().await;

    // rustls 0.23 requires a process-global CryptoProvider when multiple are in
    // the dep graph. Install one for the test (idempotent / ignore if already
    // installed by another component).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Best-effort tracing init for tests; ignored if already set. Honors
    // RUST_LOG, defaults to a quiet level otherwise.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let tmp = tempfile::tempdir().unwrap();

    // origin
    let origin_ca = Arc::new(TestCa::new());
    let (leaf_cert, leaf_key) = origin_ca.mint("localhost");
    let key_bytes = match &leaf_key {
        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der().to_vec(),
        PrivateKeyDer::Sec1(k) => k.secret_sec1_der().to_vec(),
        _ => panic!("unsupported private key variant"),
    };
    let rustls_cfg = RustlsConfig::from_der(vec![leaf_cert.as_ref().to_vec()], key_bytes)
        .await
        .unwrap();
    let hits = HitCounter::default();
    let app_state = OriginState { hits: hits.clone() };
    let app = Router::new()
        .route(
            "/echo/:msg",
            get(
                |State(s): State<OriginState>, Path(msg): Path<String>| async move {
                    s.hits.bump(&format!("/echo/{msg}"));
                    msg
                },
            ),
        )
        .route(
            "/big/:n",
            get(
                |State(s): State<OriginState>, Path(n): Path<usize>| async move {
                    s.hits.bump(&format!("/big/{n}"));
                    "x".repeat(n)
                },
            ),
        )
        .route(
            "/boom",
            get(|State(s): State<OriginState>| async move {
                s.hits.bump("/boom");
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "oops")
            }),
        )
        // `/cacheable` returns a fixed body; convenient for miss-then-hit
        // assertions where the test wants a stable identity for the URL.
        .route(
            "/cacheable",
            get(|State(s): State<OriginState>| async move {
                s.hits.bump("/cacheable");
                "cacheable-body"
            }),
        )
        // `/status/:code` returns an arbitrary status code with a small body.
        // The optional `?p=` is just a cache-key/marker so multiple variants
        // can co-exist; we count hits including the query string.
        .route(
            "/status/:code",
            get(
                |State(s): State<OriginState>,
                 Path(code): Path<u16>,
                 Query(q): Query<HashMap<String, String>>| async move {
                    let p = q.get("p").cloned().unwrap_or_default();
                    s.hits.bump(&format!("/status/{code}?p={p}"));
                    let status = axum::http::StatusCode::from_u16(code)
                        .unwrap_or(axum::http::StatusCode::OK);
                    (status, format!("status={code}"))
                },
            ),
        )
        // `/echo-headers` returns the request headers in the body, one per
        // line. Tests use this to verify that the X-Roxy-Fingerprint header
        // is stripped before upstream forwarding.
        .route(
            "/echo-headers",
            get(
                |State(s): State<OriginState>, headers: HeaderMap| async move {
                    s.hits.bump("/echo-headers");
                    let mut out = String::new();
                    let mut names: Vec<_> = headers.iter().collect();
                    names.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
                    for (k, v) in names {
                        out.push_str(k.as_str());
                        out.push_str(": ");
                        out.push_str(v.to_str().unwrap_or("<binary>"));
                        out.push('\n');
                    }
                    out
                },
            ),
        )
        .with_state(app_state);
    let origin_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_addr: SocketAddr = origin_listener.local_addr().unwrap();
    let origin_handle = tokio::spawn(async move {
        axum_server::from_tcp_rustls(origin_listener, rustls_cfg)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    // Point rustls-native-certs at the origin CA so roxy's upstream client
    // trusts the test origin. Must be set BEFORE roxy is spawned (the
    // HttpsConnector reads roots when constructed).
    let origin_ca_path = tmp.path().join("origin-ca.pem");
    std::fs::write(&origin_ca_path, &origin_ca.cert_pem).unwrap();
    // Env mutation must happen before any concurrent reader. We set it before
    // spawning the roxy task; integration tests in `tests/` are compiled as
    // separate binaries so this only affects the current test process.
    std::env::set_var("SSL_CERT_FILE", &origin_ca_path);

    // Optionally also feed the same PEM to roxy's impersonate client via the
    // dedicated test env var. wreq's `webpki-roots` default store does NOT
    // consult SSL_CERT_FILE.
    if b.inject_origin_ca_into_wreq {
        std::env::set_var("ROXY_TEST_EXTRA_ROOT_PEM_PATH", &origin_ca_path);
    } else {
        std::env::remove_var("ROXY_TEST_EXTRA_ROOT_PEM_PATH");
    }

    // roxy: bind a TcpListener so we know the port, then run
    let roxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let roxy_addr: SocketAddr = roxy_listener.local_addr().unwrap();
    drop(roxy_listener); // free port; race-ish but fine for tests
    let cfg_path = tmp.path().join("roxy.toml");
    let cache_dir = tmp.path().join("cache");
    let mut cfg_text = format!(
        r#"
listen = "{roxy_addr}"
[cache]
enabled = {}
dir = "{}"
default_ttl_seconds = {}
[ca]
dir = "{}"
[log]
level = "warn"
"#,
        b.cache_enabled,
        cache_dir.display(),
        b.default_ttl_seconds,
        tmp.path().join("ca").display(),
    );
    let needs_impersonate_section = b.default_profile.is_some() || b.profiles_dir.is_some();
    if needs_impersonate_section {
        cfg_text.push_str("[impersonate]\n");
        if let Some(name) = &b.default_profile {
            cfg_text.push_str(&format!("default_profile = \"{name}\"\n"));
        }
        if let Some(dir) = &b.profiles_dir {
            cfg_text.push_str(&format!("profiles_dir = \"{}\"\n", dir.display()));
        }
    }
    if let Some(proxy) = &b.upstream_proxy {
        cfg_text.push_str(&format!("[upstream]\nproxy = \"{proxy}\"\n"));
    }
    std::fs::write(&cfg_path, cfg_text).unwrap();
    let roxy_cfg = roxy_config::load_from_path(&cfg_path).unwrap();
    let ca_dir = roxy_cfg.ca.dir.clone();
    let cfg_path_for_task = cfg_path.clone();
    let roxy_handle =
        tokio::spawn(
            async move { roxy_proxy_lib::serve::run(Some(&cfg_path_for_task), None).await },
        );
    // wait until listener is up
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(roxy_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let roxy_ca_pem = std::fs::read_to_string(ca_dir.join("roxy-ca.crt")).unwrap();

    Fixture {
        roxy_addr,
        origin_addr,
        origin_host: format!("localhost:{}", origin_addr.port()),
        roxy_ca_pem,
        origin_ca,
        hits,
        cache_dir,
        _origin_handle: origin_handle,
        _roxy_handle: roxy_handle,
        _tmp: tmp,
    }
}
