#![allow(clippy::unwrap_used)]

mod common;

use common::spawn_fixture;
use std::time::Duration;

#[tokio::test]
async fn expired_entry_is_missed_and_refetched() {
    // ttl = 1s
    let f = spawn_fixture(1).await;
    let proxy_url = format!("http://{}", f.roxy_addr);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(
            reqwest::Certificate::from_pem(f.origin_ca.cert_pem.as_bytes()).unwrap(),
        )
        .build()
        .unwrap();
    let url = format!("https://{}/echo/x", f.origin_host);
    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "x");
}
