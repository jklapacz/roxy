use crate::connect::{read_connect, write_200};
use roxy_mitm::Terminator;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, warn};

pub type Handler = Arc<dyn ConnHandler + Send + Sync>;

#[async_trait::async_trait]
pub trait ConnHandler: Send + Sync {
    async fn handle(
        &self,
        authority: String,
        tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    );
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
            let host = match read_connect(&mut sock).await {
                Ok(Some(h)) => h,
                Ok(None) => {
                    warn!(?peer, "non-CONNECT first request dropped");
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
            handler.handle(host, tls).await;
        });
    }
}
