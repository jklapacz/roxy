use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::time::Duration;
use thiserror::Error;

/// Body type accepted by [`UpstreamClient::send`]. Generic over a boxed
/// `http_body::Body` so callers can forward arbitrary request bodies (e.g.
/// streamed POSTs) through the upstream pool.
pub type ClientBody = BoxBody<bytes::Bytes, std::io::Error>;

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("client: {0}")]
    Client(#[from] hyper_util::client::legacy::Error),

    #[error("invalid uri: {0}")]
    Uri(String),
}

#[derive(Clone)]
pub struct UpstreamClient {
    inner: Client<hyper_rustls::HttpsConnector<HttpConnector>, ClientBody>,
}

impl UpstreamClient {
    pub fn new() -> Result<Self, UpstreamError> {
        // Ensure a process-global rustls CryptoProvider is installed. When multiple
        // backends (e.g. `ring` + `aws-lc-rs`) are present in the dep graph rustls
        // cannot auto-select; install `ring` explicitly. Ignore the result: if
        // another component already installed a provider that is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();

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
            .build::<_, ClientBody>(https);
        Ok(Self { inner })
    }

    /// Send a request with a streaming [`ClientBody`].
    pub async fn send(
        &self,
        req: Request<ClientBody>,
    ) -> Result<Response<Incoming>, UpstreamError> {
        Ok(self.inner.request(req).await?)
    }

    /// Send a request with an empty body. Internally converts to a [`ClientBody`]
    /// so it shares the same connection pool as [`Self::send`].
    pub async fn send_empty(
        &self,
        req: Request<Empty<bytes::Bytes>>,
    ) -> Result<Response<Incoming>, UpstreamError> {
        let (parts, body) = req.into_parts();
        let body: ClientBody = body.map_err(|never| match never {}).boxed();
        let req = Request::from_parts(parts, body);
        Ok(self.inner.request(req).await?)
    }
}
