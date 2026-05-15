//! In-process fake HTTP CONNECT proxy for integration tests. Reads the
//! `CONNECT host:port` request, records the target (and any
//! `Proxy-Authorization` header), then either tunnels to the real target or
//! rejects with a canned status.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

/// What the fake proxy does after reading a CONNECT request.
#[derive(Clone, Copy)]
pub enum ProxyBehavior {
    /// Reply `200` and splice bytes to the real CONNECT target.
    Tunnel,
    /// Reply `407 Proxy Authentication Required` and close.
    Reject407,
}

pub struct FakeProxy {
    pub addr: SocketAddr,
    /// CONNECT targets seen, in arrival order (e.g. "localhost:54321").
    pub connects: Arc<Mutex<Vec<String>>>,
    /// `Proxy-Authorization` header values seen (None when absent), per conn.
    pub auth: Arc<Mutex<Vec<Option<String>>>>,
    _handle: JoinHandle<()>,
}

impl FakeProxy {
    pub async fn spawn(behavior: ProxyBehavior) -> FakeProxy {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connects = Arc::new(Mutex::new(Vec::new()));
        let auth = Arc::new(Mutex::new(Vec::new()));
        let connects_c = connects.clone();
        let auth_c = auth.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                let connects = connects_c.clone();
                let auth = auth_c.clone();
                tokio::spawn(async move {
                    let _ = handle_conn(&mut client, behavior, connects, auth).await;
                });
            }
        });
        FakeProxy {
            addr,
            connects,
            auth,
            _handle: handle,
        }
    }

    /// Number of CONNECT requests seen for the exact `host:port` target.
    pub fn connect_count(&self, target: &str) -> usize {
        self.connects
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.as_str() == target)
            .count()
    }

    /// All `Proxy-Authorization` header values observed.
    pub fn auth_values(&self) -> Vec<Option<String>> {
        self.auth.lock().unwrap().clone()
    }
}

async fn handle_conn(
    client: &mut TcpStream,
    behavior: ProxyBehavior,
    connects: Arc<Mutex<Vec<String>>>,
    auth: Arc<Mutex<Vec<Option<String>>>>,
) -> std::io::Result<()> {
    // Read the request header block byte-at-a-time up to "\r\n\r\n".
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte).await?;
        if n == 0 {
            return Ok(());
        }
        buf.push(byte[0]);
        if buf.len() > 8192 {
            return Ok(());
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("");
    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    let auth_value = lines.find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("proxy-authorization") {
            Some(v.trim().to_string())
        } else {
            None
        }
    });
    connects.lock().unwrap().push(target.clone());
    auth.lock().unwrap().push(auth_value);

    match behavior {
        ProxyBehavior::Reject407 => {
            client
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await?;
            Ok(())
        }
        ProxyBehavior::Tunnel => {
            let mut upstream = match TcpStream::connect(&target).await {
                Ok(s) => s,
                Err(_) => {
                    client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        .await?;
                    return Ok(());
                }
            };
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            tokio::io::copy_bidirectional(client, &mut upstream).await?;
            Ok(())
        }
    }
}
