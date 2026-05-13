#![allow(clippy::unwrap_used)]
#![allow(dead_code)]

pub mod trust;

use axum::{routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::PrivateKeyDer;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use trust::TestCa;

pub struct Fixture {
    pub roxy_addr: SocketAddr,
    pub origin_addr: SocketAddr,
    pub origin_host: String,
    pub roxy_ca_pem: String,
    pub origin_ca: Arc<TestCa>,
    _origin_handle: JoinHandle<()>,
    _roxy_handle: JoinHandle<anyhow::Result<()>>,
    _tmp: TempDir,
}

pub async fn spawn_fixture(default_ttl_seconds: u64) -> Fixture {
    // rustls 0.23 requires a process-global CryptoProvider when multiple are in
    // the dep graph. Install one for the test (idempotent / ignore if already
    // installed by another component).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = tempfile::tempdir().unwrap();

    // origin
    let origin_ca = Arc::new(TestCa::new());
    let (leaf_cert, leaf_key) = origin_ca.mint("localhost");
    let key_bytes = match &leaf_key {
        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
        PrivateKeyDer::Pkcs1(k) => k.secret_pkcs1_der().to_vec(),
        PrivateKeyDer::Sec1(k) => k.secret_sec1_der().to_vec(),
        _ => panic!("unsupported private key variant"),
    };
    let rustls_cfg = RustlsConfig::from_der(vec![leaf_cert.as_ref().to_vec()], key_bytes)
        .await
        .unwrap();
    let app = Router::new()
        .route(
            "/echo/:msg",
            get(|axum::extract::Path(msg): axum::extract::Path<String>| async move { msg }),
        )
        .route(
            "/big/:n",
            get(|axum::extract::Path(n): axum::extract::Path<usize>| async move { "x".repeat(n) }),
        )
        .route(
            "/boom",
            get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "oops") }),
        );
    let origin_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_addr: SocketAddr = origin_listener.local_addr().unwrap();
    let origin_handle = tokio::spawn(async move {
        axum_server::from_tcp_rustls(origin_listener, rustls_cfg)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    // Point rustls-native-certs at the origin CA so roxy's upstream client
    // trusts the test origin. Must be set BEFORE roxy is spawned (the
    // HttpsConnector reads roots when constructed).
    let origin_ca_path = tmp.path().join("origin-ca.pem");
    std::fs::write(&origin_ca_path, &origin_ca.cert_pem).unwrap();
    // Env mutation must happen before any concurrent reader. We set it before
    // spawning the roxy task; integration tests in `tests/` are compiled as
    // separate binaries so this only affects the current test process.
    std::env::set_var("SSL_CERT_FILE", &origin_ca_path);

    // roxy: bind a TcpListener so we know the port, then run
    let roxy_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let roxy_addr: SocketAddr = roxy_listener.local_addr().unwrap();
    drop(roxy_listener); // free port; race-ish but fine for tests
    let cfg_path = tmp.path().join("roxy.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
listen = "{roxy_addr}"
[cache]
dir = "{}"
default_ttl_seconds = {default_ttl_seconds}
[ca]
dir = "{}"
[log]
level = "warn"
"#,
            tmp.path().join("cache").display(),
            tmp.path().join("ca").display(),
        ),
    )
    .unwrap();
    let roxy_cfg = roxy_config::load_from_path(&cfg_path).unwrap();
    let ca_dir = roxy_cfg.ca.dir.clone();
    let cfg_path_for_task = cfg_path.clone();
    let roxy_handle =
        tokio::spawn(
            async move { roxy_proxy_lib::serve::run(Some(&cfg_path_for_task), None).await },
        );
    // wait until listener is up
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(roxy_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let roxy_ca_pem = std::fs::read_to_string(ca_dir.join("roxy-ca.crt")).unwrap();

    Fixture {
        roxy_addr,
        origin_addr,
        origin_host: format!("localhost:{}", origin_addr.port()),
        roxy_ca_pem,
        origin_ca,
        _origin_handle: origin_handle,
        _roxy_handle: roxy_handle,
        _tmp: tmp,
    }
}
