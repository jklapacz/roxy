//! Ring 2 integration tests for TLS/HTTP/2 fingerprint emulation.
//!
//! These exercise routing, caching, header handling, and config plumbing —
//! NOT raw fingerprint fidelity (that lives in Ring 3 / Task 9 against a
//! public network endpoint).
//!
//! The fake origin used by the fixture is HTTPS, signed by a test CA that
//! roxy's rustls upstream trusts via `SSL_CERT_FILE`. wreq does NOT consult
//! `SSL_CERT_FILE`, so tests that need the impersonate path end-to-end must
//! call `FixtureBuilder::inject_origin_ca_into_wreq()`, which feeds the same
//! PEM via the `ROXY_TEST_EXTRA_ROOT_PEM_PATH` env var that
//! `roxy_proxy_lib::serve::build_impersonate` reads.

#![allow(clippy::unwrap_used)]

mod common;

use common::FixtureBuilder;
use roxy_proxy_lib::handler::FINGERPRINT_HEADER;

/// Helper that builds a reqwest client wired through roxy, trusting both the
/// roxy MITM CA and the fake origin's CA.
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
async fn impersonate_default_miss_then_hit() {
    let f = FixtureBuilder::new()
        .default_profile("chrome-137")
        .inject_origin_ca_into_wreq()
        .build()
        .await;
    let c = client(&f);
    let url = f.fake_origin_url("/cacheable");

    let r1 = c.get(&url).send().await.unwrap();
    assert_eq!(r1.status(), 200);
    let b1 = r1.text().await.unwrap();
    assert_eq!(b1, "cacheable-body");

    // The tee_pump that finalizes the cache entry runs in a spawned task.
    // For a fast small body the index row is usually written by the time
    // r1.text() returns, but it is not guaranteed — a brief yield gives the
    // background task time to commit before we issue the second request.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let r2 = c.get(&url).send().await.unwrap();
    assert_eq!(r2.status(), 200);
    let b2 = r2.text().await.unwrap();
    assert_eq!(b1, b2);

    // Only one upstream hit because the second request was served from cache.
    assert_eq!(f.upstream_hit_count("/cacheable"), 1);
}

#[tokio::test]
async fn profile_partition_in_cache() {
    let f = FixtureBuilder::new()
        .inject_origin_ca_into_wreq()
        .build()
        .await;
    let c = client(&f);
    let url = f.fake_origin_url("/cacheable");

    // Two different fingerprints => two distinct cache keys => two upstream
    // hits even though the URL is the same.
    let r1 = c
        .get(&url)
        .header(FINGERPRINT_HEADER, "chrome-137")
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);
    let _ = r1.text().await.unwrap();

    let r2 = c
        .get(&url)
        .header(FINGERPRINT_HEADER, "firefox-139")
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 200);
    let _ = r2.text().await.unwrap();

    assert_eq!(f.upstream_hit_count("/cacheable"), 2);

    // Give the cache writer background tasks a chance to commit before we
    // re-request — see the comment in `impersonate_default_miss_then_hit`
    // for why this is needed (tee_pump → writer.finish() is asynchronous).
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // And a repeat of either fingerprint should now hit the cache.
    let r3 = c
        .get(&url)
        .header(FINGERPRINT_HEADER, "chrome-137")
        .send()
        .await
        .unwrap();
    assert_eq!(r3.status(), 200);
    assert_eq!(f.upstream_hit_count("/cacheable"), 2);
}

#[tokio::test]
async fn none_opts_out_of_default() {
    // No CA injection: the impersonate path would FAIL against the fake
    // origin because wreq does not trust the test CA. The rustls path works
    // because it consults SSL_CERT_FILE. This asymmetry is what lets us
    // prove the `none` header takes the rustls path: a `none` request must
    // succeed, and a request that exercises the default (`chrome-137`,
    // through wreq) must fail with 502.
    let f = FixtureBuilder::new()
        .default_profile("chrome-137")
        .build()
        .await;
    let c = client(&f);
    let url = f.fake_origin_url("/cacheable");

    // `none` => rustls path => success.
    let r_none = c
        .get(&url)
        .header(FINGERPRINT_HEADER, "none")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_none.status(),
        200,
        "X-Roxy-Fingerprint: none should take the rustls path and succeed"
    );
    assert_eq!(r_none.text().await.unwrap(), "cacheable-body");
    assert_eq!(f.upstream_hit_count("/cacheable"), 1);

    // Default (chrome-137) => wreq path => wreq does not trust the test CA
    // => roxy maps the TLS error to a 502.
    let r_default = c.get(&url).send().await.unwrap();
    assert_eq!(
        r_default.status(),
        502,
        "default profile path must fail without wreq trust, proving the two paths are distinct"
    );
}

#[tokio::test]
async fn unknown_profile_returns_502() {
    let f = FixtureBuilder::new().build().await;
    let c = client(&f);
    let url = f.fake_origin_url("/cacheable");

    let r = c
        .get(&url)
        .header(FINGERPRINT_HEADER, "chrome-999")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 502);

    // No upstream call should have been attempted because the profile fails
    // to resolve before any network IO.
    assert_eq!(f.upstream_hit_count("/cacheable"), 0);
}

#[tokio::test]
async fn five_xx_pass_through_impersonate() {
    let f = FixtureBuilder::new()
        .default_profile("chrome-137")
        .inject_origin_ca_into_wreq()
        .build()
        .await;
    let c = client(&f);
    let url = f.fake_origin_url_status(503, "five-xx");

    let r1 = c.get(&url).send().await.unwrap();
    assert_eq!(r1.status(), 503);

    // A second identical request must still hit the origin: 5xx responses
    // are pass-through and never cached.
    let r2 = c.get(&url).send().await.unwrap();
    assert_eq!(r2.status(), 503);

    let key = "/status/503?p=five-xx";
    assert_eq!(f.upstream_hit_count(key), 2);
}

#[tokio::test]
async fn custom_profile_loads_and_serves() {
    // Drop a minimal custom profile into a tempdir, configure roxy to load
    // from that dir, then request via the custom name.
    let profiles_tmp = tempfile::tempdir().unwrap();
    let custom_path = profiles_tmp.path().join("test-custom.toml");
    std::fs::write(
        &custom_path,
        r#"
name = "test-custom"

[tls]
alpn = ["h2", "http/1.1"]
cipher_suites = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
]
extensions = ["server_name", "supported_groups", "key_share", "supported_versions"]
supported_versions = ["TLS1.3", "TLS1.2"]
signature_algorithms = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_frame_size = 16384
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE"]
header_order = [":method", ":authority", ":scheme", ":path"]
"#,
    )
    .unwrap();

    let f = FixtureBuilder::new()
        .profiles_dir(profiles_tmp.path())
        .inject_origin_ca_into_wreq()
        .build()
        .await;
    let c = client(&f);
    let url = f.fake_origin_url("/cacheable");

    let r = c
        .get(&url)
        .header(FINGERPRINT_HEADER, "test-custom")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "custom profile must dispatch through the wreq path"
    );
    assert_eq!(r.text().await.unwrap(), "cacheable-body");
    assert_eq!(f.upstream_hit_count("/cacheable"), 1);

    // Keep profiles_tmp alive for the lifetime of the fixture.
    drop(profiles_tmp);
}

#[tokio::test]
async fn fingerprint_header_stripped_upstream() {
    let f = FixtureBuilder::new()
        .default_profile("chrome-137")
        .inject_origin_ca_into_wreq()
        .build()
        .await;
    let c = client(&f);
    let url = f.fake_origin_url("/echo-headers");

    let r = c
        .get(&url)
        .header(FINGERPRINT_HEADER, "firefox-139")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body = r.text().await.unwrap();
    let lower = body.to_ascii_lowercase();
    assert!(
        !lower.contains("x-roxy-fingerprint"),
        "X-Roxy-Fingerprint must be stripped before upstream forwarding; got body:\n{body}"
    );
}
