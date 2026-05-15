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

/// Perform the HTTP CONNECT handshake on an already-open TCP stream to the
/// proxy. On success the stream is an opaque tunnel to `host:port`.
async fn connect_tunnel(
    tcp: &mut TcpStream,
    host: &str,
    port: u16,
    auth: Option<&ProxyAuth>,
) -> Result<(), BoxError> {
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(a) = auth {
        let creds = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", a.username, a.password));
        req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes()).await?;

    let raw = read_connect_response(tcp).await?;
    let status = parse_status_line(&raw)?;
    if status != 200 {
        return Err(format!("upstream proxy refused CONNECT: status {status}").into());
    }
    Ok(())
}

/// Read a proxy's CONNECT response header block (status line + headers up to
/// the terminating `\r\n\r\n`). Reads one byte at a time so we never consume
/// past the header terminator into the tunnel body — the proxy sends nothing
/// after the response until we send tunnel data, so this cannot under-read.
async fn read_connect_response(tcp: &mut TcpStream) -> Result<Vec<u8>, BoxError> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = tcp.read(&mut byte).await?;
        if n == 0 {
            return Err("upstream proxy closed connection during CONNECT".into());
        }
        buf.push(byte[0]);
        if buf.len() > MAX_CONNECT_RESPONSE {
            return Err("upstream proxy CONNECT response header block too large".into());
        }
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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

    /// Spawn a one-shot fake proxy: accept a connection, read the request
    /// header block (up to `\r\n\r\n`) into the returned buffer, write
    /// `response`, then close. Returns the listen addr and the captured
    /// request bytes (filled once a client connects).
    async fn fake_proxy_endpoint(
        response: &'static [u8],
    ) -> (std::net::SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_c = captured.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = sock.read(&mut byte).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            *captured_c.lock().unwrap() = buf;
            let _ = sock.write_all(response).await;
        });
        (addr, captured)
    }

    #[tokio::test]
    async fn connect_tunnel_succeeds_on_200() {
        let (addr, captured) =
            fake_proxy_endpoint(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        connect_tunnel(&mut tcp, "example.com", 443, None)
            .await
            .unwrap();
        let req = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
            "got: {req:?}"
        );
        assert!(!req.contains("Proxy-Authorization"), "got: {req:?}");
    }

    #[tokio::test]
    async fn connect_tunnel_sends_basic_auth() {
        let (addr, captured) =
            fake_proxy_endpoint(b"HTTP/1.1 200 Connection Established\r\n\r\n").await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let auth = ProxyAuth {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        connect_tunnel(&mut tcp, "example.com", 443, Some(&auth))
            .await
            .unwrap();
        let req = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        // base64("user:pass") == "dXNlcjpwYXNz"
        assert!(
            req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
            "got: {req:?}"
        );
    }

    #[tokio::test]
    async fn connect_tunnel_errors_on_407() {
        let (addr, _captured) =
            fake_proxy_endpoint(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let err = connect_tunnel(&mut tcp, "example.com", 443, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("407"), "got: {err}");
    }

    #[tokio::test]
    async fn connect_tunnel_errors_when_proxy_closes() {
        let (addr, _captured) = fake_proxy_endpoint(b"").await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let err = connect_tunnel(&mut tcp, "example.com", 443, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("closed"), "got: {err}");
    }
}
