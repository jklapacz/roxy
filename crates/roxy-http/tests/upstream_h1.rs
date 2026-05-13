#![allow(clippy::unwrap_used)]

use axum::routing::get;
use axum::Router;
use roxy_http::UpstreamClient;
use std::net::SocketAddr;

#[tokio::test]
async fn h1_get_works() {
    let app = Router::new().route("/hello", get(|| async { "world" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = UpstreamClient::new().unwrap();
    let uri = format!("http://{addr}/hello").parse::<http::Uri>().unwrap();
    let req = http::Request::get(uri)
        .body(http_body_util::Empty::new())
        .unwrap();
    let resp = client.send_empty(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}
