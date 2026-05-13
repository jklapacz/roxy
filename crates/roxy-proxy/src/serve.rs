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

fn build_impersonate(cfg: &Config) -> anyhow::Result<Option<roxy_impersonate::ImpersonateClient>> {
    let customs = roxy_impersonate::CustomProfile::load_dir(&cfg.impersonate.profiles_dir)
        .context("load custom profiles")?;
    if cfg.impersonate.default_profile.is_none() && customs.is_empty() {
        return Ok(None);
    }
    let client = roxy_impersonate::ImpersonateClient::with_custom(customs);
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
