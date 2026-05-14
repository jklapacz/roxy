#![allow(clippy::unwrap_used)]

//! Integration test for `[cache] enabled = false`: roxy still MITMs and
//! proxies every request end-to-end, but never serves from or writes to the
//! cache. This keeps the fingerprint + MITM core flow exercised in isolation.

mod common;

use common::FixtureBuilder;

#[tokio::test]
async fn cache_disabled_never_serves_or_writes() {
    let f = FixtureBuilder::new().cache_enabled(false).build().await;
    let proxy_url = format!("http://{}", f.roxy_addr);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .add_root_certificate(
            reqwest::Certificate::from_pem(f.origin_ca.cert_pem.as_bytes()).unwrap(),
        )
        .build()
        .unwrap();

    let url = f.fake_origin_url("/cacheable");

    // Two requests to the same cacheable URL — the full MITM + proxy flow runs
    // for each, and the response is still correct.
    let r1 = client.get(&url).send().await.unwrap();
    assert_eq!(r1.status(), 200);
    assert_eq!(r1.text().await.unwrap(), "cacheable-body");

    let r2 = client.get(&url).send().await.unwrap();
    assert_eq!(r2.status(), 200);
    assert_eq!(r2.text().await.unwrap(), "cacheable-body");

    // Cache disabled => the second request is NOT served from cache, so the
    // origin is hit both times.
    assert_eq!(
        f.upstream_hit_count("/cacheable"),
        2,
        "cache disabled: every request must reach the origin"
    );

    // Cache disabled => nothing was written to the cache directory.
    assert!(
        f.cache_dir_is_empty(),
        "cache disabled: the cache directory must stay free of entries"
    );
}
