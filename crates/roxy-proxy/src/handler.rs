use crate::cache_directives;
use crate::finalize_signal::FinalizeSignal;
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
    /// When false, skip cache lookup (serve) and store (write) entirely — every
    /// request is MITM'd and proxied as normal, just never cached.
    pub cache_enabled: bool,
    pub default_ttl: Duration,
    pub router: Arc<UpstreamRouter>,
    pub default_profile: Option<String>,
    pub strip_fingerprint_header: bool,
    pub disconnect_cap: u64,
    /// Fires whenever `tee_pump` consumes a cache writer. Production code
    /// constructs and ignores this; the integration-test fixture awaits it
    /// to avoid the 200ms sleep workaround for tee_pump finalization
    /// (see `roxy-2w1` and `crate::finalize_signal`).
    pub finalize_signal: Arc<FinalizeSignal>,
}

pub const FINGERPRINT_HEADER: &str = "x-roxy-fingerprint";

impl<C: Cache + 'static> Handler<C> {
    pub async fn handle_tunneled(
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

        // 2. Strip header before forwarding upstream (config-gated).
        if self.strip_fingerprint_header {
            req.headers_mut().remove(FINGERPRINT_HEADER);
        }

        self.handle_inner(label, authority, "https", req).await
    }

    pub async fn handle_plain(
        &self,
        mut req: http::Request<hyper::body::Incoming>,
    ) -> Result<http::Response<BoxBody>, std::convert::Infallible> {
        // 1. Extract the absolute-form target (authority + scheme).
        let (authority, scheme) = match extract_plain_target(req.uri()) {
            Ok(t) => t,
            Err(_) => {
                return Ok(simple(
                    http::StatusCode::BAD_REQUEST,
                    "roxy: HTTP request missing absolute-form URI",
                ));
            }
        };

        // 2. Plain HTTP strict-ignores X-Roxy-Fingerprint. Strip it
        //    unconditionally; never honor it. See spec, "Non-goals".
        req.headers_mut().remove(FINGERPRINT_HEADER);

        // 3. Force routing through the rustls (_default) path. Fingerprint
        //    has no meaningful effect over plain HTTP and is documented
        //    as such.
        let label = DEFAULT_LABEL.to_string();

        self.handle_inner(label, authority, &scheme, req).await
    }

    async fn handle_inner(
        &self,
        label: String,
        authority: String,
        scheme: &str,
        mut req: Request<hyper::body::Incoming>,
    ) -> Result<Response<BoxBody>, Infallible> {
        // 3. Cache key. Built unconditionally — the host-mismatch warning it
        //    emits is part of the core flow even when caching is disabled.
        let key = build_cache_key_and_warn(&req, &label, scheme, &authority);
        if self.cache_enabled {
            if let Ok(Some(hit)) = self.cache.lookup(&key, &[]).await {
                return Ok(reply_from_cache(hit));
            }
        }

        // 4. Rebuild upstream URI (authority is supplied by the caller, path comes from the request).
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
                let chain = error_chain(&e);
                tracing::warn!(error = %e, error_chain = %chain, profile = %label, host = %authority, kind = %kind, "upstream send failed");
                return Ok(bad_gateway("roxy: upstream error"));
            }
        };

        let status = resp.status();
        let (resp_parts, resp_body) = resp.into_parts();
        let directives = cache_directives::parse(&resp_parts.headers);
        let status_eligible = status.is_success() || status.is_redirection();
        let cache_eligible = status_eligible && directives.should_cache();

        // Build writer only when caching is enabled and this response is
        // eligible. With caching disabled, `writer` stays None and `tee_pump`
        // streams straight through to the client.
        let writer: Option<Box<dyn CacheWriter>> = if self.cache_enabled && cache_eligible {
            let meta = roxy_cache::ResponseMeta {
                status: status.as_u16(),
                headers: header_pairs(&resp_parts.headers),
            };
            let ttl = directives.effective_ttl(self.default_ttl);
            match self.cache.begin_store(&key, meta, ttl, &[]).await {
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
        let finalize_signal = self.finalize_signal.clone();
        tokio::spawn(tee_pump(
            resp_body,
            writer,
            tx,
            disconnect_cap,
            finalize_signal,
        ));

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
    finalize_signal: Arc<FinalizeSignal>,
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
                    finalize_signal.record();
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
                    finalize_signal.record();
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
                    finalize_signal.record();
                }
                return;
            }
        }
    }

    if let Some(w) = writer.take() {
        if let Err(e) = w.finish().await {
            tracing::warn!(error = %e, "cache finalize failed");
        }
        finalize_signal.record();
    }
}

fn header_pairs(h: &http::HeaderMap) -> Vec<(String, Vec<u8>)> {
    h.iter()
        .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
        .collect()
}

fn bad_gateway(msg: &'static str) -> Response<BoxBody> {
    simple(StatusCode::BAD_GATEWAY, msg)
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
        Some(v) => match v.to_str() {
            Ok(s) => s.trim(),
            Err(_) => return Err(LabelError::BadValue("<non-ascii>".to_string())),
        },
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

fn client_authority<B>(req: &Request<B>) -> Option<String> {
    if let Some(a) = req.uri().authority() {
        return Some(a.as_str().to_string());
    }
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn authority_matches(connect: &str, client: &str) -> bool {
    fn normalize(s: &str) -> String {
        let lower = s.to_ascii_lowercase();
        lower
            .strip_suffix(":443")
            .map(|s| s.to_string())
            .unwrap_or(lower)
    }
    normalize(connect) == normalize(client)
}

/// Extract the target from an absolute-form request URI.
///
/// Returns `Ok((authority, scheme))` — authority first, scheme second.
/// Returns `Err` with a static message when the URI has no authority
/// (e.g. a path-only request-target, which is invalid for a forward proxy).
fn extract_plain_target(uri: &http::Uri) -> Result<(String, String), &'static str> {
    let authority = uri
        .authority()
        .ok_or("missing absolute-form authority")?
        .as_str()
        .to_string();
    let scheme = uri.scheme_str().unwrap_or("http").to_string();
    Ok((authority, scheme))
}

fn build_cache_key_and_warn<B>(
    req: &Request<B>,
    label: &str,
    scheme: &str,
    authority: &str,
) -> CacheKey {
    let host_for_key = authority.to_ascii_lowercase();
    let key = CacheKey::from_parts(
        label,
        req.method().as_str(),
        scheme,
        &host_for_key,
        req.uri().path(),
        req.uri().query(),
    );

    if let Some(client_host) = client_authority(req) {
        if !authority_matches(authority, &client_host) {
            tracing::warn!(
                connect_authority = %authority,
                client_host = %client_host,
                kind = "host_mismatch",
                "client Host/URI authority disagrees with CONNECT authority; \
                 keying by CONNECT authority"
            );
        }
    }
    key
}

/// Walk the error's `source()` chain and join each step's Display with `" -> "`.
/// Surfaces causes that the top-level `Display` hides (e.g. wreq wraps its
/// transport errors as `"client error (Connect)"` and stuffs the real cause in
/// `source()`).
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut current = e.source();
    while let Some(err) = current {
        out.push_str(" -> ");
        out.push_str(&err.to_string());
        current = err.source();
    }
    out
}

fn upstream_kind(e: &UpstreamError) -> &'static str {
    match e {
        UpstreamError::Impersonate(roxy_impersonate::ImpersonateError::RequestBodyCollect(_)) => {
            "impersonate_body_collect"
        }
        UpstreamError::Impersonate(_) => "impersonate",
        UpstreamError::Client(_) => "rustls_client",
        UpstreamError::Uri(_) => "uri",
        UpstreamError::UnknownFingerprint(_) => {
            unreachable!("handled directly in Handler::handle_inner")
        }
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

    #[test]
    fn non_ascii_value_error() {
        let mut h = HeaderMap::new();
        let bytes: &[u8] = b"\xff\xfe";
        let val = http::HeaderValue::from_bytes(bytes).unwrap();
        h.append(FINGERPRINT_HEADER, val);
        match resolve_label(&h, None).unwrap_err() {
            LabelError::BadValue(v) => assert_eq!(v, "<non-ascii>"),
            other => panic!("got {other:?}"),
        }
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;
    use http::Request;
    use roxy_cache::CacheKey;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured_warnings(f: impl FnOnce()) -> String {
        let writer = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let data = writer.0.lock().unwrap().clone();
        String::from_utf8(data).unwrap()
    }

    #[test]
    fn cache_key_uses_connect_authority() {
        let req = Request::get("/api")
            .header(http::header::HOST, "attacker.com")
            .body(())
            .unwrap();
        let key = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");
        let expected = CacheKey::from_parts("p", "GET", "https", "bank.com:443", "/api", None);
        assert_eq!(key, expected);
    }

    #[test]
    fn host_mismatch_emits_warning() {
        let req = Request::get("/api")
            .header(http::header::HOST, "attacker.com")
            .body(())
            .unwrap();
        let output = captured_warnings(|| {
            let _ = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");
        });
        assert!(
            output.contains("kind=\"host_mismatch\""),
            "expected host_mismatch warning, got: {output}"
        );
        assert!(
            output.contains("connect_authority=bank.com:443"),
            "expected connect_authority in warning, got: {output}"
        );
        assert!(
            output.contains("client_host=attacker.com"),
            "expected client_host in warning, got: {output}"
        );
    }

    #[test]
    fn matching_host_does_not_warn() {
        let req = Request::get("/api")
            .header(http::header::HOST, "bank.com")
            .body(())
            .unwrap();
        let output = captured_warnings(|| {
            let _ = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");
        });
        assert!(
            !output.contains("host_mismatch"),
            "expected no warning for matching host (default port stripped), got: {output}"
        );
    }

    #[test]
    fn absolute_form_uri_matching_connect_authority_does_not_warn() {
        let req = Request::get("https://bank.com/api").body(()).unwrap();
        let output = captured_warnings(|| {
            let _ = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");
        });
        assert!(
            !output.contains("host_mismatch"),
            "expected no warning when absolute-form URI matches CONNECT authority (after default-port strip), got: {output}"
        );
    }

    #[test]
    fn cache_key_uses_http_scheme_differs_from_https() {
        let req = Request::get("http://bank.com/api").body(()).unwrap();
        let http_key = build_cache_key_and_warn(&req, "p", "http", "bank.com:443");
        let https_key = build_cache_key_and_warn(&req, "p", "https", "bank.com:443");
        assert_ne!(
            http_key, https_key,
            "scheme must participate in the cache key"
        );
    }

    #[test]
    fn extract_plain_target_absolute_form_http() {
        let uri: http::Uri = "http://example.com/path".parse().unwrap();
        let (authority, scheme) = extract_plain_target(&uri).unwrap();
        assert_eq!(authority, "example.com");
        assert_eq!(scheme, "http");
    }

    #[test]
    fn extract_plain_target_preserves_port() {
        let uri: http::Uri = "http://example.com:8080/path".parse().unwrap();
        let (authority, _) = extract_plain_target(&uri).unwrap();
        assert_eq!(authority, "example.com:8080");
    }

    #[test]
    fn extract_plain_target_path_only_errors() {
        let uri: http::Uri = "/path".parse().unwrap();
        let err = extract_plain_target(&uri).unwrap_err();
        assert!(err.contains("authority"), "got: {err}");
    }
}
