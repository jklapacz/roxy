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

    // Opt-in TLS-fingerprint capture server on its own port. It reuses the
    // MITM terminator (CA-backed cert resolver) and writes captured profiles
    // into the same directory the impersonate path loads them from.
    if cfg.capture.enabled {
        let capture_listen = cfg.capture.listen;
        let capture_terminator = terminator.clone();
        let capture_profiles_dir = cfg.impersonate.profiles_dir.clone();
        tokio::spawn(async move {
            if let Err(e) =
                roxy_capture::run(capture_listen, capture_terminator, capture_profiles_dir).await
            {
                tracing::error!(error = %e, "capture server exited");
            }
        });
        tracing::info!(addr = %cfg.capture.listen, "capture server enabled");
    }

    let rustls = roxy_http::UpstreamClient::new().context("upstream client")?;
    let impersonate = build_impersonate(&cfg)?;
    let router = Arc::new(roxy_http::UpstreamRouter::new(rustls, impersonate));

    let handler = ProxyConnHandler {
        inner: Arc::new(Handler {
            cache: cache.clone(),
            cache_enabled: cfg.cache.enabled,
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
            let client =
                roxy_impersonate::ImpersonateClient::with_custom_and_extra_root_pem(customs, &pem)
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
    async fn handle_tunneled(
        &self,
        authority: String,
        tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) {
        let inner = self.inner.clone();
        let authority_clone = authority.clone();
        roxy_http::serve_tls(tls, move |req| {
            let inner = inner.clone();
            let authority = authority_clone.clone();
            async move { inner.handle_tunneled(authority, req).await }
        })
        .await;
    }

    async fn handle_plain(&self, stream: tokio::net::TcpStream) {
        let inner = self.inner.clone();
        roxy_http::serve_http_plain(stream, move |req| {
            let inner = inner.clone();
            async move { inner.handle_plain(req).await }
        })
        .await;
    }
}
