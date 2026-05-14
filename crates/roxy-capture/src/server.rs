//! The standalone capture server: accept loop + per-connection orchestration.

use crate::stream::{lock, PrefixedStream, RecordingStream, RECORD_CAP};
use crate::{client_hello, h2, profile};
use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use roxy_impersonate::ProfileName;
use roxy_mitm::Terminator;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

type BoxBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

/// How long to wait for the ClientHello bytes before giving up on a connection.
const HELLO_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on the ClientHello record size we will buffer.
const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// Run the capture server until the listener fails.
///
/// Each accepted connection has its raw ClientHello parsed, completes a MITM
/// TLS handshake via `terminator`, and is served one HTTP response that echoes
/// the captured profile TOML (also written to `profiles_dir`).
pub async fn run(
    listen: SocketAddr,
    terminator: Terminator,
    profiles_dir: PathBuf,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| anyhow::anyhow!("bind capture listener {listen}: {e}"))?;
    tracing::info!(addr = %listen, "capture server listening");
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "capture accept error");
                continue;
            }
        };
        let terminator = terminator.clone();
        let profiles_dir = profiles_dir.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(sock, terminator, profiles_dir).await {
                tracing::warn!(?peer, error = %e, "capture connection failed");
            }
        });
    }
}

async fn handle_conn(
    mut sock: TcpStream,
    terminator: Terminator,
    profiles_dir: PathBuf,
) -> anyhow::Result<()> {
    // Read the raw ClientHello off the socket so it can be parsed, then replay
    // it to the rustls acceptor via PrefixedStream.
    let hello_bytes = read_client_hello(&mut sock).await?;
    let captured_tls = client_hello::parse(&hello_bytes)?;

    let prefixed = PrefixedStream::new(hello_bytes, sock);
    let tls = terminator
        .acceptor()
        .accept(prefixed)
        .await
        .map_err(|e| anyhow::anyhow!("tls handshake: {e}"))?;
    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);

    // Tee the decrypted client→server bytes so the HTTP/2 frames can be parsed
    // once hyper has produced the first request.
    let record = Arc::new(Mutex::new(Vec::<u8>::with_capacity(RECORD_CAP)));
    let recording = RecordingStream::new(tls, record.clone());

    let captured_tls = Arc::new(captured_tls);
    let svc = service_fn(move |req: Request<Incoming>| {
        let captured_tls = captured_tls.clone();
        let record = record.clone();
        let profiles_dir = profiles_dir.clone();
        let alpn = alpn.clone();
        async move {
            Ok::<_, Infallible>(respond(
                req,
                &captured_tls,
                &record,
                &profiles_dir,
                alpn.as_deref(),
            ))
        }
    });

    auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(recording), svc)
        .await
        .map_err(|e| anyhow::anyhow!("serve capture connection: {e}"))
}

/// Read from the socket until a full TLS record (the ClientHello) is buffered.
/// Returns every byte read, so the caller can replay them to the TLS acceptor.
async fn read_client_hello(sock: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    loop {
        if buf.len() >= 5 {
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= 5 + record_len {
                return Ok(buf);
            }
        }
        if buf.len() > MAX_CLIENT_HELLO {
            anyhow::bail!("ClientHello exceeds {MAX_CLIENT_HELLO} bytes");
        }
        let n = tokio::time::timeout(HELLO_READ_TIMEOUT, sock.read(&mut tmp))
            .await
            .map_err(|_| anyhow::anyhow!("timed out reading ClientHello"))?
            .map_err(|e| anyhow::anyhow!("read ClientHello: {e}"))?;
        if n == 0 {
            anyhow::bail!("connection closed before a full ClientHello arrived");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn respond(
    req: Request<Incoming>,
    captured_tls: &client_hello::CapturedTls,
    record: &Mutex<Vec<u8>>,
    profiles_dir: &Path,
    alpn: Option<&[u8]>,
) -> Response<BoxBody> {
    let name = match resolve_name(req.uri().query()) {
        Ok(n) => n,
        Err(msg) => return text(StatusCode::BAD_REQUEST, msg),
    };

    let recorded = lock(record).clone();
    let captured_http2 = h2::parse_http2(&recorded);
    let toml = profile::render(&name, captured_tls, captured_http2.as_ref(), alpn);

    let mut body = String::new();
    match profile::write_profile(profiles_dir, &name, &toml) {
        Ok(path) => {
            tracing::info!(profile = %name.as_str(), path = %path.display(), "captured TLS profile");
            body.push_str(&format!(
                "# roxy-capture: profile written to {}\n",
                path.display()
            ));
        }
        Err(e) => {
            tracing::warn!(profile = %name.as_str(), error = %e, "failed to write captured profile");
            body.push_str(&format!(
                "# roxy-capture: WARNING — failed to write profile file: {e}\n"
            ));
        }
    }
    body.push_str(&toml);
    text(StatusCode::OK, body)
}

/// Resolve the profile name from the `?name=` query parameter, falling back to
/// `captured-<unix-ts>`. Returns a static error message on an invalid name.
fn resolve_name(query: Option<&str>) -> Result<ProfileName, &'static str> {
    match query.and_then(name_param) {
        Some(v) => ProfileName::parse(&v)
            .map_err(|_| "roxy-capture: ?name= must match ^[a-z0-9][a-z0-9-]*$\n"),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            ProfileName::parse(&format!("captured-{ts}"))
                .map_err(|_| "roxy-capture: could not build a default profile name\n")
        }
    }
}

fn name_param(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix("name="))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn text(status: StatusCode, body: impl Into<Bytes>) -> Response<BoxBody> {
    let b = Full::new(body.into())
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut resp = Response::new(b);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_param_extracts_value() {
        assert_eq!(name_param("name=my-chrome"), Some("my-chrome".to_string()));
        assert_eq!(
            name_param("foo=1&name=edge-99&bar=2"),
            Some("edge-99".to_string())
        );
        assert_eq!(name_param("foo=1"), None);
        assert_eq!(name_param("name="), None);
    }

    #[test]
    fn resolve_name_defaults_when_absent() {
        let n = resolve_name(None).unwrap();
        assert!(n.as_str().starts_with("captured-"));
    }

    #[test]
    fn resolve_name_rejects_invalid() {
        assert!(resolve_name(Some("name=Bad_Name")).is_err());
    }

    #[test]
    fn resolve_name_accepts_valid() {
        assert_eq!(
            resolve_name(Some("name=chrome-148")).unwrap().as_str(),
            "chrome-148"
        );
    }
}
