//! End-to-end integration tests for upstream proxy support. roxy is
//! configured with `[upstream] proxy` pointing at an in-process fake CONNECT
//! proxy; the tests assert traffic actually tunnels through it.

#![allow(clippy::unwrap_used)]

mod common;

use common::fake_proxy::{FakeProxy, ProxyBehavior};
use common::FixtureBuilder;

/// reqwest client wired through roxy, trusting roxy's MITM CA and the fake
/// origin's CA.
fn client(f: &common::Fixture) -> reqwest::Client {
    let proxy_url = format!("http://{}", f.roxy_addr);
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(
            reqwest::Certificate::from_pem(f.origin_ca.cert_pem.as_bytes()).unwrap(),
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn rustls_path_tunnels_through_proxy() {
    let proxy = FakeProxy::spawn(ProxyBehavior::Tunnel).await;
    let f = FixtureBuilder::new()
        .upstream_proxy(format!("http://{}", proxy.addr))
        .build()
        .await;
    let c = client(&f);

    let r = c
        .get(f.fake_origin_url("/echo/hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "hello");

    // The request reached the origin *via* the fake proxy.
    assert_eq!(proxy.connect_count(&f.origin_host), 1);
}

#[tokio::test]
async fn wreq_path_tunnels_through_proxy() {
    let proxy = FakeProxy::spawn(ProxyBehavior::Tunnel).await;
    let f = FixtureBuilder::new()
        .default_profile("chrome-137")
        .inject_origin_ca_into_wreq()
        .upstream_proxy(format!("http://{}", proxy.addr))
        .build()
        .await;
    let c = client(&f);

    let r = c
        .get(f.fake_origin_url("/echo/world"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "world");

    assert_eq!(proxy.connect_count(&f.origin_host), 1);
}

#[tokio::test]
async fn proxy_basic_auth_is_sent() {
    let proxy = FakeProxy::spawn(ProxyBehavior::Tunnel).await;
    let f = FixtureBuilder::new()
        .upstream_proxy(format!("http://user:pass@{}", proxy.addr))
        .build()
        .await;
    let c = client(&f);

    let r = c.get(f.fake_origin_url("/echo/auth")).send().await.unwrap();
    assert_eq!(r.status(), 200);

    // base64("user:pass") == "dXNlcjpwYXNz"
    let auth = proxy.auth_values();
    assert!(
        auth.iter()
            .any(|v| v.as_deref() == Some("Basic dXNlcjpwYXNz")),
        "expected Proxy-Authorization header; saw: {auth:?}"
    );
}

#[tokio::test]
async fn proxy_rejection_surfaces_as_502() {
    let proxy = FakeProxy::spawn(ProxyBehavior::Reject407).await;
    let f = FixtureBuilder::new()
        .upstream_proxy(format!("http://{}", proxy.addr))
        .build()
        .await;
    let c = client(&f);

    // roxy's upstream client fails the CONNECT; roxy returns 502 to the client.
    let r = c.get(f.fake_origin_url("/echo/nope")).send().await.unwrap();
    assert_eq!(r.status(), 502);
}
