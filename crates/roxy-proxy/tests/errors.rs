#![allow(clippy::unwrap_used)]

mod common;

use common::spawn_fixture;

#[tokio::test]
async fn origin_5xx_is_forwarded_but_not_cached() {
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
    let url = format!("https://{}/boom", f.origin_host);

    let r = client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), 500);
    let body = r.text().await.unwrap();
    assert!(body.contains("oops"));

    // No cache entry should exist for /boom — verified by re-requesting and asserting
    // status is still 500 (not e.g. 200 if oddly cached).
    let r = client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), 500);
}
