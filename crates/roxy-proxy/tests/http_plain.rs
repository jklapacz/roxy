#![allow(clippy::unwrap_used)]

//! End-to-end integration test for plain HTTP forward-proxying.
//!
//! Spawns a plain-HTTP axum origin and roxy on random ports, then sends
//! a request through reqwest configured with an HTTP proxy. Verifies
//! status/body and miss-then-hit cache behavior.

use axum::{extract::State, routing::get, Router};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

#[derive(Clone, Default)]
struct OriginState {
    hits: Arc<Mutex<usize>>,
}

async fn spawn_origin() -> (SocketAddr, Arc<Mutex<usize>>) {
    let state = OriginState::default();
    let hits = state.hits.clone();
    let app = Router::new()
        .route(
            "/cacheable",
            get(|State(s): State<OriginState>| async move {
                *s.hits.lock().unwrap() += 1;
                "plain-cacheable-body"
            }),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, hits)
}

async fn spawn_roxy() -> (SocketAddr, TempDir) {
    // rustls global provider (idempotent).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = tempfile::tempdir().unwrap();

    // Bind a free port then drop the listener; roxy rebinds it.
    let scratch = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let roxy_addr: SocketAddr = scratch.local_addr().unwrap();
    drop(scratch); // free port; race-ish but fine for tests

    let cfg_path = tmp.path().join("roxy.toml");
    let cfg_text = format!(
        r#"
listen = "{roxy_addr}"
[cache]
dir = "{}"
default_ttl_seconds = 3600
[ca]
dir = "{}"
[log]
level = "warn"
"#,
        tmp.path().join("cache").display(),
        tmp.path().join("ca").display(),
    );
    std::fs::write(&cfg_path, cfg_text).unwrap();

    let cfg_path_for_task = cfg_path.clone();
    tokio::spawn(async move { roxy_proxy_lib::serve::run(Some(&cfg_path_for_task), None).await });

    // Wait until the proxy listener accepts connections.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(roxy_addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        tokio::net::TcpStream::connect(roxy_addr).await.is_ok(),
        "roxy failed to start within 2.5s at {roxy_addr}"
    );
    (roxy_addr, tmp)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_http_request_is_proxied_and_cached() {
    let (origin_addr, hits) = spawn_origin().await;
    let (roxy_addr, _tmp) = spawn_roxy().await;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{roxy_addr}")).unwrap())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/cacheable", origin_addr.port());

    // First request — origin should be hit once.
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "plain-cacheable-body");
    assert_eq!(
        *hits.lock().unwrap(),
        1,
        "origin should be hit once on miss"
    );

    // The tee_pump that finalizes the cache entry runs in a spawned task.
    // For a fast small body the index row is usually written by the time
    // resp.text() returns, but it is not guaranteed — a brief yield gives the
    // background task time to commit before we issue the second request.
    // (Same pattern used in tests/impersonate.rs:impersonate_default_miss_then_hit.)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Second request — must hit cache, origin count unchanged.
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "plain-cacheable-body");
    assert_eq!(
        *hits.lock().unwrap(),
        1,
        "second request must be served from cache (origin hit count must not increment)"
    );
}
