#![allow(clippy::unwrap_used)]

//! End-to-end tests for response `Vary` handling. Drives the fake origin's
//! `/vary?mode=accept|star` route to make it emit either `Vary: Accept`
//! (variant routing) or `Vary: *` (uncacheable). Asserts that requests with
//! different Vary'd headers do not cross-serve and that `Vary: *` is never
//! stored.

mod common;

use common::{spawn_fixture, FixtureBuilder};

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

fn vary_url(f: &common::Fixture, mode: &str) -> String {
    format!("https://{}/vary?mode={}", f.origin_host, mode)
}

#[tokio::test]
async fn different_accept_get_different_responses() {
    let f = spawn_fixture(3600).await;
    let client = build_client(&f);
    let url = vary_url(&f, "accept");

    let r_json = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(r_json.text().await.unwrap(), "body-for-application/json");
    f.wait_for_n_finalizations(1).await;

    let r_html = client
        .get(&url)
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(r_html.text().await.unwrap(), "body-for-text/html");
    f.wait_for_n_finalizations(1).await;

    assert_eq!(
        f.upstream_hit_count("/vary?mode=accept"),
        2,
        "different Accept values must each reach the origin (no cross-serve)"
    );
}

#[tokio::test]
async fn same_accept_hits_cache() {
    let f = FixtureBuilder::new()
        .default_ttl_seconds(3600)
        .build()
        .await;
    let client = build_client(&f);
    let url = vary_url(&f, "accept");

    let _ = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    f.wait_for_n_finalizations(1).await;

    let r2 = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(r2.text().await.unwrap(), "body-for-application/json");

    assert_eq!(
        f.upstream_hit_count("/vary?mode=accept"),
        1,
        "same Accept value must be served from cache on the second request"
    );
}

#[tokio::test]
async fn vary_star_not_cached() {
    let f = spawn_fixture(3600).await;
    let client = build_client(&f);
    let url = vary_url(&f, "star");

    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();
    let _ = client.get(&url).send().await.unwrap().text().await.unwrap();

    assert_eq!(
        f.upstream_hit_count("/vary?mode=star"),
        2,
        "Vary: * must never be cached"
    );
    assert!(
        f.cache_dir_is_empty(),
        "Vary: *: nothing should be persisted to disk"
    );
}
