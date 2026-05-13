#![allow(clippy::unwrap_used)]

mod common;

use common::spawn_fixture;

#[tokio::test]
#[ignore = "smoke: requires internet"]
async fn httpbin_get_via_roxy() {
    let f = spawn_fixture(3600).await;
    let proxy_url = format!("http://{}", f.roxy_addr);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .danger_accept_invalid_hostnames(true) // tolerate fixture quirks
        .build()
        .unwrap();
    let r1 = client
        .get("https://httpbin.org/anything")
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);
    let r2 = client
        .get("https://httpbin.org/anything")
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);
}
