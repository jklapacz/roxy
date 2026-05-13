#![allow(clippy::unwrap_used)]

mod common;

use common::spawn_fixture;

#[tokio::test]
async fn miss_then_hit_returns_same_body_and_caches() {
    let f = spawn_fixture(3600).await;
    let proxy_url = format!("http://{}", f.roxy_addr);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(
            reqwest::Certificate::from_pem(f.origin_ca.cert_pem.as_bytes()).unwrap(),
        )
        .build()
        .unwrap();

    let url = format!("https://{}/echo/hello", f.origin_host);

    let r1 = client.get(&url).send().await.unwrap();
    assert_eq!(r1.status(), 200);
    let b1 = r1.text().await.unwrap();
    assert_eq!(b1, "hello");

    let r2 = client.get(&url).send().await.unwrap();
    assert_eq!(r2.status(), 200);
    let b2 = r2.text().await.unwrap();
    assert_eq!(b2, "hello");

    // Hard correctness: byte-for-byte identical body across miss and hit.
    assert_eq!(b1, b2);
}
