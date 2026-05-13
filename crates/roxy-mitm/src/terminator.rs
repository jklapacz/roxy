use crate::resolver::SniResolver;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
pub struct Terminator {
    acceptor: TlsAcceptor,
}

impl Terminator {
    pub fn new(resolver: Arc<SniResolver>) -> Self {
        static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        INIT.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        Self { acceptor }
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ca::Ca, leaf::LeafSigner, resolver::SniResolver};
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    #[tokio::test]
    async fn handshake_succeeds_against_terminator() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let signer = LeafSigner::new(ca.clone());
        let resolver = Arc::new(SniResolver::new(signer, NonZeroUsize::new(8).unwrap()));
        let terminator = Terminator::new(resolver);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // server
        let acceptor = terminator.acceptor();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"HELLO");
            tls.write_all(b"OK").await.unwrap();
            tls.shutdown().await.unwrap();
        });

        // client trusting our CA
        let mut roots = rustls::RootCertStore::empty();
        let pem = ca.cert_pem.as_bytes();
        for c in rustls_pemfile::certs(&mut std::io::Cursor::new(pem)).flatten() {
            roots.add(c).unwrap();
        }
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(config));
        let sock = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("example.com").unwrap();
        let mut tls = connector.connect(server_name, sock).await.unwrap();
        tls.write_all(b"HELLO").await.unwrap();
        let mut resp = [0u8; 2];
        tls.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"OK");
    }
}
