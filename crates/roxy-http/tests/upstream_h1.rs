#![allow(clippy::unwrap_used)]

use axum::routing::get;
use axum::Router;
use roxy_http::UpstreamClient;
use std::net::SocketAddr;

async fn spawn_h1_origin() -> SocketAddr {
    let app = Router::new().route("/hello", get(|| async { "world" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn h1_get_works() {
    let addr = spawn_h1_origin().await;

    let client = UpstreamClient::new().unwrap();
    let uri = format!("http://{addr}/hello").parse::<http::Uri>().unwrap();
    let req = http::Request::get(uri)
        .body(http_body_util::Empty::new())
        .unwrap();
    let resp = client.send_empty(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

/// A request that arrives at roxy over HTTP/2 (browser↔roxy is h2) carries
/// `version = HTTP/2`. The browser hop and the upstream hop are independent —
/// the upstream connection's protocol is whatever ALPN negotiates. When the
/// origin only speaks HTTP/1.1, an HTTP/2-versioned upstream request must NOT
/// hard-fail with `UserUnsupportedVersion`; `UpstreamClient` normalizes the
/// request version so hyper-util's legacy client uses the negotiated protocol.
#[tokio::test]
async fn h2_versioned_request_to_h1_origin_does_not_fail() {
    let addr = spawn_h1_origin().await;

    let client = UpstreamClient::new().unwrap();
    let uri = format!("http://{addr}/hello").parse::<http::Uri>().unwrap();
    let req = http::Request::get(uri)
        .version(http::Version::HTTP_2)
        .body(http_body_util::Empty::new())
        .unwrap();
    let resp = client.send_empty(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}
