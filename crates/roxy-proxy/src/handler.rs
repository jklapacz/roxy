use bytes::Bytes;
use futures::TryStreamExt;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use roxy_cache::{Cache, CacheKey};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

/// Body type used for responses produced by the handler.
///
/// We use `UnsyncBoxBody` rather than `BoxBody` because cache hits stream from a
/// `futures::stream::BoxStream` which is only `Send` (not `Sync`).
pub type BoxBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

#[derive(Clone)]
pub struct Handler<C: Cache + 'static> {
    pub cache: Arc<C>,
    pub default_ttl: Duration,
    pub upstream: roxy_http::UpstreamClient,
    pub disconnect_cap: u64,
}

impl<C: Cache + 'static> Handler<C> {
    pub async fn handle(
        &self,
        authority: String,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody>, Infallible> {
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

/// Build a `BoxBody` from a static byte slice. Infallible: `Full` never errors,
/// so the `map_err` closure is unreachable.
fn static_body(bytes: &'static [u8]) -> BoxBody {
    Full::new(Bytes::from_static(bytes))
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// Construct a response from a cache hit. We construct via `Response::new` +
/// `status_mut`/`headers_mut` (rather than `Response::builder()...body().unwrap()`)
/// to avoid a production `.unwrap()` and satisfy `clippy::unwrap_used`. Header
/// values that fail to parse back into `HeaderName`/`HeaderValue` are skipped.
/// A `from_u16` failure on the status falls back to 200.
fn reply_from_cache(hit: roxy_cache::CachedResponse) -> Response<BoxBody> {
    let status = StatusCode::from_u16(hit.meta.status).unwrap_or(StatusCode::OK);
    let stream = hit
        .body
        .map_ok(http_body::Frame::data)
        .map_err(std::io::Error::from);
    let body: BoxBody = StreamBody::new(stream).boxed_unsync();

    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    for (k, v) in &hit.meta.headers {
        if let (Ok(name), Ok(val)) = (
            http::HeaderName::from_bytes(k.as_bytes()),
            http::HeaderValue::from_bytes(v),
        ) {
            headers.append(name, val);
        }
    }
    resp
}

/// Placeholder miss-path response. Task 18 replaces this with the
/// tee-while-caching upstream proxy.
fn not_implemented_yet() -> Response<BoxBody> {
    let mut resp = Response::new(static_body(b"miss path not implemented"));
    *resp.status_mut() = StatusCode::NOT_IMPLEMENTED;
    resp
}
