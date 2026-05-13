use bytes::Bytes;
use futures::TryStreamExt;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody};
use roxy_cache::{Cache, CacheKey, CacheWriter};
use roxy_http::{UpstreamError, UpstreamRouter};
use roxy_impersonate::{DEFAULT_LABEL, NONE_LABEL};
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
    pub router: Arc<UpstreamRouter>,
    pub default_profile: Option<String>,
    pub strip_fingerprint_header: bool,
    pub disconnect_cap: u64,
}

pub const FINGERPRINT_HEADER: &str = "x-roxy-fingerprint";

impl<C: Cache + 'static> Handler<C> {
    pub async fn handle(
        &self,
        authority: String,
        mut req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody>, Infallible> {
        // 1. Resolve profile label.
        let label = match resolve_label(req.headers(), self.default_profile.as_deref()) {
            Ok(l) => l,
            Err(LabelError::MultipleHeaders) => {
                return Ok(simple(
                    StatusCode::BAD_REQUEST,
                    "roxy: X-Roxy-Fingerprint must be set at most once",
                ));
            }
            Err(LabelError::BadValue(_)) => {
                return Ok(simple(
                    StatusCode::BAD_REQUEST,
                    "roxy: X-Roxy-Fingerprint value must match ^[a-z0-9][a-z0-9-]*$",
                ));
            }
        };

        // 2. Strip header before forwarding upstream.
        if self.strip_fingerprint_header {
            req.headers_mut().remove(FINGERPRINT_HEADER);
        }

        // 3. Cache key includes the label.
        let key = CacheKey::from_request(&req, &label, "https", &authority);
        if let Ok(Some(hit)) = self.cache.lookup(&key).await {
            return Ok(reply_from_cache(hit));
        }

        // 4. Rebuild upstream URI (authority is from CONNECT, path comes from inner request).
        let scheme = req.uri().scheme_str().unwrap_or("https");
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let upstream_uri: http::Uri =
            match format!("{scheme}://{authority}{path_and_query}").parse() {
                Ok(u) => u,
                Err(_) => return Ok(bad_gateway("roxy: bad upstream uri")),
            };
        *req.uri_mut() = upstream_uri;
        req.headers_mut().remove(http::header::HOST);

        // 5. Forward via router.
        let (parts, body) = req.into_parts();
        let body: roxy_http::ClientBody = body.map_err(std::io::Error::other).boxed();
        let upstream_req = http::Request::from_parts(parts, body);

        let resp = match self.router.send(&label, upstream_req).await {
            Ok(r) => r,
            Err(UpstreamError::UnknownFingerprint(name)) => {
                tracing::warn!(profile = %name, host = %authority, kind = "unknown_profile", "unknown fingerprint");
                return Ok(bad_gateway("roxy: unknown fingerprint"));
            }
            Err(e) => {
                let kind = upstream_kind(&e);
                tracing::warn!(error = %e, profile = %label, host = %authority, kind = %kind, "upstream send failed");
                return Ok(bad_gateway("roxy: upstream error"));
            }
        };

        let status = resp.status();
        let cache_eligible = status.is_success() || status.is_redirection();
        let (resp_parts, resp_body) = resp.into_parts();

        // Build writer only when caching this response.
        let writer: Option<Box<dyn CacheWriter>> = if cache_eligible {
            let meta = roxy_cache::ResponseMeta {
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
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);
        let disconnect_cap = self.disconnect_cap;
        tokio::spawn(tee_pump(resp_body, writer, tx, disconnect_cap));

        let mut builder_resp = http::Response::new(stream_to_body(rx));
        *builder_resp.status_mut() = resp_parts.status;
        for (k, v) in resp_parts.headers.iter() {
            builder_resp.headers_mut().append(k, v.clone());
        }
        Ok(builder_resp)
    }
}

fn stream_to_body(rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>) -> BoxBody {
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map_ok(http_body::Frame::data);
    StreamBody::new(stream).boxed_unsync()
}

async fn tee_pump<B>(
    mut upstream: B,
    mut writer: Option<Box<dyn CacheWriter>>,
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    disconnect_cap: u64,
) where
    B: http_body::Body<Data = Bytes, Error = std::io::Error> + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut client_alive = true;
    let mut bytes_past_disconnect = 0u64;
    while let Some(frame) = http_body_util::BodyExt::frame(&mut upstream).await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                if let Some(w) = writer.take() {
                    w.abort();
                }
                tx.send(Err(std::io::Error::other(e))).await.ok();
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
                if let Some(w) = writer.take() {
                    w.abort();
                }
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
                tracing::warn!(
                    cap = disconnect_cap,
                    "exceeded post-disconnect cap; aborting cache write"
                );
                if let Some(w) = writer.take() {
                    w.abort();
                }
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
    let body = Full::new(Bytes::from_static(msg.as_bytes()))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut resp = http::Response::new(body);
    *resp.status_mut() = StatusCode::BAD_GATEWAY;
    resp
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

#[derive(Debug, PartialEq)]
enum LabelError {
    MultipleHeaders,
    BadValue(String),
}

fn resolve_label(
    headers: &http::HeaderMap,
    default_profile: Option<&str>,
) -> Result<String, LabelError> {
    let mut iter = headers.get_all(FINGERPRINT_HEADER).iter();
    let first = iter.next();
    if iter.next().is_some() {
        return Err(LabelError::MultipleHeaders);
    }
    let raw = match first {
        Some(v) => v.to_str().unwrap_or("").trim(),
        None => "",
    };
    if raw.is_empty() {
        return Ok(default_profile.unwrap_or(DEFAULT_LABEL).to_string());
    }
    if raw == NONE_LABEL {
        return Ok(DEFAULT_LABEL.to_string());
    }
    if roxy_impersonate::ProfileName::parse(raw).is_err() {
        return Err(LabelError::BadValue(raw.to_string()));
    }
    Ok(raw.to_string())
}

fn upstream_kind(e: &UpstreamError) -> &'static str {
    match e {
        UpstreamError::UnknownFingerprint(_) => "unknown_profile",
        UpstreamError::Impersonate(roxy_impersonate::ImpersonateError::Wreq(_)) => "impersonate",
        UpstreamError::Impersonate(_) => "impersonate_other",
        UpstreamError::Client(_) => "rustls_client",
        UpstreamError::Uri(_) => "uri",
    }
}

fn simple(status: StatusCode, msg: &'static str) -> Response<BoxBody> {
    let body = Full::new(Bytes::from_static(msg.as_bytes()))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut resp = http::Response::new(body);
    *resp.status_mut() = status;
    resp
}

#[cfg(test)]
mod label_tests {
    use super::*;
    use http::HeaderMap;

    fn hdr(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(FINGERPRINT_HEADER, http::HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn absent_header_uses_default_or_default_label() {
        let h = HeaderMap::new();
        assert_eq!(resolve_label(&h, None).unwrap(), DEFAULT_LABEL);
        assert_eq!(resolve_label(&h, Some("chrome-137")).unwrap(), "chrome-137");
    }

    #[test]
    fn empty_value_treated_as_absent() {
        let h = hdr(&[""]);
        assert_eq!(resolve_label(&h, Some("chrome-137")).unwrap(), "chrome-137");
    }

    #[test]
    fn none_forces_default_label() {
        let h = hdr(&["none"]);
        assert_eq!(
            resolve_label(&h, Some("chrome-137")).unwrap(),
            DEFAULT_LABEL
        );
    }

    #[test]
    fn explicit_known_name_used() {
        let h = hdr(&["firefox-139"]);
        assert_eq!(
            resolve_label(&h, Some("chrome-137")).unwrap(),
            "firefox-139"
        );
    }

    #[test]
    fn multiple_headers_error() {
        let h = hdr(&["chrome-137", "firefox-139"]);
        assert_eq!(
            resolve_label(&h, None).unwrap_err(),
            LabelError::MultipleHeaders
        );
    }

    #[test]
    fn malformed_value_error() {
        let h = hdr(&["Chrome_137"]);
        match resolve_label(&h, None).unwrap_err() {
            LabelError::BadValue(v) => assert_eq!(v, "Chrome_137"),
            other => panic!("got {other:?}"),
        }
    }
}
