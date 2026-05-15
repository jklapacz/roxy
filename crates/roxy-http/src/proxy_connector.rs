//! `ProxyConnector` — a `tower::Service<Uri>` that optionally CONNECT-tunnels
//! through an upstream HTTP proxy before the TLS layer runs. When no proxy is
//! configured it delegates straight to `HttpConnector`, byte-identical to the
//! direct path.

use base64::Engine as _;
use http::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use roxy_config::{ProxyAuth, ProxyEndpoint};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tower_service::Service;

/// Boxed connector error — unifies `HttpConnector`'s error with our own
/// `io::Error`s from the CONNECT handshake.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Maximum bytes buffered while reading a proxy's CONNECT response header
/// block. A well-behaved proxy's response is tiny; the cap stops a
/// misbehaving proxy from making us buffer without bound.
const MAX_CONNECT_RESPONSE: usize = 8 * 1024;

/// Parse the status code out of an HTTP/1.x response header block. Expects a
/// first line shaped like `HTTP/1.1 200 Connection Established`.
fn parse_status_line(raw: &[u8]) -> Result<u16, BoxError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| -> BoxError { "proxy CONNECT response is not valid UTF-8".into() })?;
    let first = text
        .lines()
        .next()
        .ok_or_else(|| -> BoxError { "empty proxy CONNECT response".into() })?;
    let mut parts = first.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(format!("malformed proxy CONNECT status line: {first:?}").into());
    }
    let code = parts
        .next()
        .ok_or_else(|| -> BoxError { format!("missing status code in: {first:?}").into() })?;
    code.parse::<u16>()
        .map_err(|_| format!("non-numeric status code in: {first:?}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_200() {
        let raw = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        assert_eq!(parse_status_line(raw).unwrap(), 200);
    }

    #[test]
    fn parses_407() {
        let raw =
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
        assert_eq!(parse_status_line(raw).unwrap(), 407);
    }

    #[test]
    fn rejects_non_http_first_line() {
        assert!(parse_status_line(b"garbage here\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_missing_code() {
        assert!(parse_status_line(b"HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_non_numeric_code() {
        assert!(parse_status_line(b"HTTP/1.1 twohundred OK\r\n\r\n").is_err());
    }
}
