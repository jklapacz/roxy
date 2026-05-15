use crate::proxy_connector::ProxyConnector;
use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body, Frame};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;

/// Body type accepted by [`UpstreamClient::send`]. Generic over a boxed
/// `http_body::Body` so callers can forward arbitrary request bodies (e.g.
/// streamed POSTs) through the upstream pool.
pub type ClientBody = BoxBody<bytes::Bytes, std::io::Error>;

pin_project! {
    /// Body type emitted by all upstream client variants. The handler's tee_pump
    /// is generic over `http_body::Body`, so any future variant added here just
    /// needs to implement `Body<Data=Bytes, Error=io::Error>` and forward
    /// poll_frame.
    #[project = UpstreamBodyProj]
    pub enum UpstreamBody {
        Hyper { #[pin] inner: hyper::body::Incoming },
        Impersonate { #[pin] inner: roxy_impersonate::ImpersonateBody },
    }
}

impl UpstreamBody {
    pub fn hyper(inner: hyper::body::Incoming) -> Self {
        Self::Hyper { inner }
    }
    pub fn impersonate(inner: roxy_impersonate::ImpersonateBody) -> Self {
        Self::Impersonate { inner }
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        match self.project() {
            UpstreamBodyProj::Hyper { inner } => {
                inner.poll_frame(cx).map_err(std::io::Error::other)
            }
            UpstreamBodyProj::Impersonate { inner } => inner.poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            UpstreamBody::Hyper { inner } => inner.is_end_stream(),
            UpstreamBody::Impersonate { inner } => inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            UpstreamBody::Hyper { inner } => inner.size_hint(),
            UpstreamBody::Impersonate { inner } => inner.size_hint(),
        }
    }
}

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("client: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),

    #[error("invalid uri: {0}")]
    Uri(String),

    #[error("unknown fingerprint: {0}")]
    UnknownFingerprint(String),

    #[error("impersonate: {0}")]
    Impersonate(#[from] roxy_impersonate::ImpersonateError),
}

#[derive(Clone)]
pub struct UpstreamClient {
    inner: Client<hyper_rustls::HttpsConnector<ProxyConnector>, ClientBody>,
}

impl UpstreamClient {
    pub fn new() -> Result<Self, UpstreamError> {
        Self::with_proxy(None)
    }

    /// Construct an upstream client that routes outbound connections through
    /// `proxy`, or directly when `proxy` is `None`. The CONNECT tunnel (when
    /// a proxy is set) is established below the TLS layer, so TLS-to-origin
    /// behavior is identical either way.
    pub fn with_proxy(proxy: Option<roxy_config::ProxyEndpoint>) -> Result<Self, UpstreamError> {
        // Ensure a process-global rustls CryptoProvider is installed. When
        // multiple backends are present in the dep graph rustls cannot
        // auto-select; install `ring` explicitly. Ignore the result: if
        // another component already installed a provider that is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.enforce_http(false);
        let connector = ProxyConnector::new(http, proxy);
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| UpstreamError::Uri(e.to_string()))?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector);
        let inner = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(32)
            .build::<_, ClientBody>(https);
        Ok(Self { inner })
    }

    /// Send a request with a streaming [`ClientBody`].
    pub async fn send(
        &self,
        mut req: Request<ClientBody>,
    ) -> Result<Response<UpstreamBody>, UpstreamError> {
        normalize_upstream_version(&mut req);
        let resp = self.inner.request(req).await?;
        let (parts, body) = resp.into_parts();
        Ok(Response::from_parts(parts, UpstreamBody::hyper(body)))
    }

    /// Send a request with an empty body. Internally converts to a [`ClientBody`]
    /// so it shares the same connection pool as [`Self::send`].
    pub async fn send_empty(
        &self,
        req: Request<Empty<bytes::Bytes>>,
    ) -> Result<Response<UpstreamBody>, UpstreamError> {
        let (parts, body) = req.into_parts();
        let body: ClientBody = body.map_err(|never| match never {}).boxed();
        let mut req = Request::from_parts(parts, body);
        normalize_upstream_version(&mut req);
        let resp = self.inner.request(req).await?;
        let (parts, body) = resp.into_parts();
        Ok(Response::from_parts(parts, UpstreamBody::hyper(body)))
    }
}

/// Normalize the upstream request's HTTP version to `HTTP/1.1`.
///
/// The browser↔roxy hop and the roxy↔origin hop negotiate their transport
/// protocols independently (each via its own TLS ALPN). A request that reached
/// roxy over HTTP/2 carries `version = HTTP_2`, but hyper-util's legacy `Client`
/// treats `HTTP_2` as a *hard requirement* — it fails with
/// `UserUnsupportedVersion` if the upstream connection ALPN-negotiates
/// HTTP/1.1. Resetting to `HTTP_11` (the neutral "no specific version required"
/// value) lets the legacy client use whatever the upstream connection
/// negotiated — it still uses h2 when ALPN selects it.
fn normalize_upstream_version<B>(req: &mut Request<B>) {
    *req.version_mut() = http::Version::HTTP_11;
}
