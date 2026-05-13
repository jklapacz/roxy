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

/// SNI cert cache capacity. `10_000` is non-zero so `NonZeroUsize::new` always
/// returns `Some`; the `unwrap_or` fallback to `NonZeroUsize::MIN` only exists
/// to satisfy `clippy::unwrap_used` without an `expect`.
const SNI_CACHE_CAPACITY: NonZeroUsize = match NonZeroUsize::new(10_000) {
    Some(n) => n,
    None => NonZeroUsize::MIN,
};

pub async fn run(
    config_path: Option<&Path>,
    fingerprint_override: Option<&str>,
) -> anyhow::Result<()> {
    let mut cfg = load_config(config_path)?;
    if let Some(f) = fingerprint_override {
        if f == roxy_impersonate::NONE_LABEL {
            cfg.impersonate.default_profile = None;
        } else {
            cfg.impersonate.default_profile = Some(f.to_string());
        }
    }

    let cache = Arc::new(FsCache::open(&cfg.cache.dir).context("open cache")?);
    let evicted = cache.cleanup_tmp().context("cleanup tmp")?;
    if evicted > 0 {
        tracing::info!(evicted, "cleaned orphan tmp files");
    }

    let ca = Ca::load_or_create(&cfg.ca.dir).context("load/create CA")?;
    print_ca_hint(&ca);

    let signer = LeafSigner::new(ca);
    let resolver = Arc::new(SniResolver::new(signer, SNI_CACHE_CAPACITY));
    let terminator = Terminator::new(resolver);

    let rustls = roxy_http::UpstreamClient::new().context("upstream client")?;
    let impersonate = build_impersonate(&cfg)?;
    let router = Arc::new(roxy_http::UpstreamRouter::new(rustls, impersonate));

    let handler = ProxyConnHandler {
        inner: Arc::new(Handler {
            cache: cache.clone(),
            default_ttl: Duration::from_secs(cfg.cache.default_ttl_seconds),
            router,
            default_profile: cfg.impersonate.default_profile.clone(),
            strip_fingerprint_header: cfg.impersonate.strip_header,
            disconnect_cap: 50 * 1024 * 1024,
        }),
    };

    tracing::info!(addr = %cfg.listen, "listening");
    roxy_http::accept::run(cfg.listen, terminator, Arc::new(handler))
        .await
        .map_err(Into::into)
}

/// Construct the optional `ImpersonateClient` based on config.
///
/// Returns `None` when there is no configured default profile AND no custom
/// profiles are present in `profiles_dir`. This preserves the zero-overhead
/// promise: a roxy without `[impersonate]` configured does not build a wreq
/// client at all, so unfingerprinted upstream calls take the rustls path
/// with bit-identical behavior to pre-Task-6 roxy.
///
/// When a default profile is configured, this also verifies the name exists
/// in the registered set (builtins + customs), bailing fast with a listing
/// of available profiles so operators see misconfiguration at startup, not
/// at first request.
fn build_impersonate(cfg: &Config) -> anyhow::Result<Option<roxy_impersonate::ImpersonateClient>> {
    let customs = roxy_impersonate::CustomProfile::load_dir(&cfg.impersonate.profiles_dir)
        .context("load custom profiles")?;
    // Integration-test hook: when `ROXY_TEST_EXTRA_ROOT_PEM_PATH` is set,
    // build the impersonate client with that PEM as its TLS root store. This
    // lets the in-process test fixture (whose fake origin is signed by a
    // test CA) drive the wreq path end-to-end without depending on a public
    // endpoint. Production roxy never sets this env var.
    //
    // The env var also forces the impersonate client to be built even when
    // no default_profile / customs are configured — tests can then exercise
    // builtin profiles via the explicit X-Roxy-Fingerprint header.
    let test_root_pem = std::env::var("ROXY_TEST_EXTRA_ROOT_PEM_PATH")
        .ok()
        .filter(|s| !s.is_empty());
    if cfg.impersonate.default_profile.is_none() && customs.is_empty() && test_root_pem.is_none() {
        return Ok(None);
    }
    let client = match test_root_pem {
        Some(path) => {
            let pem = std::fs::read(&path)
                .with_context(|| format!("ROXY_TEST_EXTRA_ROOT_PEM_PATH={path}"))?;
            roxy_impersonate::ImpersonateClient::with_custom_and_extra_root_pem(customs, &pem)
                .context("impersonate client with extra root PEM")?
        }
        None => roxy_impersonate::ImpersonateClient::with_custom(customs),
    };
    if let Some(name) = &cfg.impersonate.default_profile {
        if !client.has_profile(name) {
            let avail = client.profile_names().join(", ");
            anyhow::bail!("unknown default profile {name:?}; available: [{avail}]");
        }
    }
    Ok(Some(client))
}

fn load_config(path: Option<&Path>) -> anyhow::Result<Config> {
    let path = path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(roxy_config::default_config_path);
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
        })
        .await;
    }
}
