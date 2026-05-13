#![allow(clippy::unwrap_used)]

mod common;

use common::spawn_fixture;

#[tokio::test]
async fn large_body_under_cap_is_cached() {
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
    // 1 MiB body — well under the 50 MiB disconnect cap.
    let url = format!("https://{}/big/1048576", f.origin_host);
    let body = client
        .get(&url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(body.len(), 1_048_576);
    // Second request must serve from cache and be byte-identical.
    let body2 = client
        .get(&url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(body, body2);
}
