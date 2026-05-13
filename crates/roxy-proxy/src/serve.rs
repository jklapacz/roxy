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
    let resolver = Arc::new(SniResolver::new(signer, SNI_CACHE_CAPACITY));
    let terminator = Terminator::new(resolver);

    let rustls = roxy_http::UpstreamClient::new().context("upstream client")?;

    // Task 7 will plumb [impersonate] config; for now we always provide an
    // ImpersonateClient with no custom profiles. Per-request X-Roxy-Fingerprint
    // for builtin profiles works immediately. default_profile = None means
    // requests without the header go through the rustls path.
    let impersonate = Some(roxy_impersonate::ImpersonateClient::new());

    let router = Arc::new(roxy_http::UpstreamRouter::new(rustls, impersonate));

    let handler = ProxyConnHandler {
        inner: Arc::new(Handler {
            cache: cache.clone(),
            default_ttl: Duration::from_secs(cfg.cache.default_ttl_seconds),
            router,
            default_profile: None,
            strip_fingerprint_header: true,
            disconnect_cap: 50 * 1024 * 1024,
        }),
    };

    tracing::info!(addr = %cfg.listen, "listening");
    roxy_http::accept::run(cfg.listen, terminator, Arc::new(handler))
        .await
        .map_err(Into::into)
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
