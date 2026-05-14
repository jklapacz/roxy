use crate::connect::{read_connect, write_200};
use roxy_mitm::Terminator;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, warn};

pub type Handler = Arc<dyn ConnHandler + Send + Sync>;

#[async_trait::async_trait]
pub trait ConnHandler: Send + Sync {
    async fn handle_tunneled(
        &self,
        authority: String,
        tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    );
    async fn handle_plain(&self, stream: tokio::net::TcpStream);
}

pub async fn run(
    listen: SocketAddr,
    terminator: Terminator,
    handler: Handler,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    loop {
        let (mut sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "accept error");
                continue;
            }
        };
        let terminator = terminator.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            let mut peek_buf = [0u8; 8];
            let n = match sock.peek(&mut peek_buf).await {
                Ok(n) => n,
                Err(e) => {
                    warn!(?peer, error = %e, "peek failed");
                    return;
                }
            };
            if n >= 8 && &peek_buf == b"CONNECT " {
                // CONNECT flow: tunneled HTTPS via MITM.
                let host = match read_connect(&mut sock).await {
                    Ok(Some(h)) => h,
                    Ok(None) => {
                        // Shouldn't happen — peek already confirmed CONNECT.
                        warn!(?peer, "peek said CONNECT but read_connect returned None");
                        return;
                    }
                    Err(e) => {
                        warn!(?peer, error = %e, "read_connect failed");
                        return;
                    }
                };
                if let Err(e) = write_200(&mut sock).await {
                    warn!(?peer, error = %e, "write 200 failed");
                    return;
                }
                let acceptor = terminator.acceptor();
                let tls = match acceptor.accept(sock).await {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(?peer, error = %e, "TLS handshake failed");
                        return;
                    }
                };
                handler.handle_tunneled(host, tls).await;
            } else {
                // Plain HTTP flow: absolute-form HTTP requests, no TLS.
                handler.handle_plain(sock).await;
            }
        });
    }
}
