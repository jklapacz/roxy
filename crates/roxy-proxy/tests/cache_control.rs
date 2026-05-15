#![allow(clippy::unwrap_used)]

//! End-to-end tests for response `Cache-Control` handling. Drives the fake
//! origin's `/cc?h=<directive>` route to make it emit specific directives,
//! then asserts roxy either skips caching, honors `max-age` as the TTL, or
//! falls back to the configured default.

mod common;

use common::{spawn_fixture, FixtureBuilder};
use std::time::Duration;

fn build_client(f: &common::Fixture) -> reqwest::Client {
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

fn cc_url(f: &common::Fixture, directive: &str) -> String {
    let encoded: String = directive
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect();
    format!("https://{}/cc?h={}", f.origin_host, encoded)
}

fn hit_key(directive: &str) -> String {
    format!("/cc?h={directive}")
}

#[tokio::test]
async fn no_store_response_is_not_cached() {
    let f = spawn_fixture(3600).await;
    let client = build_client(&f);
    let url = cc_url(&f, "no-store");

    let r1 = client.get(&url).send().await.unwrap();
    assert_eq!(r1.status(), 200);
    assert_eq!(r1.text().await.unwrap(), "cc-body");

    let r2 = client.get(&url).send().await.unwrap();
    assert_eq!(r2.status(), 200);
    assert_eq!(r2.text().await.unwrap(), "cc-body");

    assert_eq!(
        f.upstream_hit_count(&hit_key("no-store")),
        2,
        "no-store: every request must reach the origin"
    );
    assert!(
        f.cache_dir_is_empty(),
        "no-store: nothing should be persisted to disk"
    );
}

#[tokio::test]
async fn private_response_is_not_cached() {
    let f = spawn_fixture(3600).await;
    let client = build_client(&f);
    let url = cc_url(&f, "private");

    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();
    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();

    assert_eq!(
        f.upstream_hit_count(&hit_key("private")),
        2,
        "private: every request must reach the origin (roxy is a shared cache)"
    );
    assert!(
        f.cache_dir_is_empty(),
        "private: nothing should be persisted to disk"
    );
}

#[tokio::test]
async fn max_age_overrides_default_ttl() {
    // Default TTL is long; max-age=1 should make the entry expire well before
    // the default would have. The first call writes the entry; we sleep past
    // max-age and the second call must refetch (proving the configured 3600s
    // default did not apply).
    let f = FixtureBuilder::new()
        .default_ttl_seconds(3600)
        .build()
        .await;
    let client = build_client(&f);
    let url = cc_url(&f, "max-age=1");

    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();
    f.wait_for_n_finalizations(1).await;

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = client.get(&url).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "cc-body");
    assert_eq!(
        f.upstream_hit_count(&hit_key("max-age=1")),
        2,
        "request after max-age expiry must refetch (proving the 3600s default did not apply)"
    );
}

#[tokio::test]
async fn no_directive_falls_back_to_default_ttl() {
    // `/cc?h=` emits no Cache-Control header at all; the default TTL applies
    // and the second request is served from cache.
    let f = FixtureBuilder::new()
        .default_ttl_seconds(3600)
        .build()
        .await;
    let client = build_client(&f);
    let url = cc_url(&f, "");

    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();
    f.wait_for_n_finalizations(1).await;
    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();

    assert_eq!(
        f.upstream_hit_count(&hit_key("")),
        1,
        "no directive: default TTL applies, second request is a cache hit"
    );
}
