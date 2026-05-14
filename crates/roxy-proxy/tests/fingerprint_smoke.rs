//! Ring 3 fingerprint fidelity smoke tests. `#[ignore]` because they require
//! public network access. Run with:
//!   cargo test -p roxy-proxy --test fingerprint_smoke -- --ignored --nocapture
//!
//! These tests are operator-run gates, not CI tests. They prove that wreq's
//! emitted bytes still match the expected fingerprint for each shipped
//! builtin profile, end-to-end through roxy.
//!
//! If `tls.peet.ws/api/all` is unreachable, swap to another fingerprint echo
//! service (e.g. `https://api.browserleaks.com/tls`) and adjust the field
//! accesses.
//!
//! Path of a request:
//!   test client (reqwest, trusts roxy CA) → roxy (MITM, terminates TLS)
//!     → wreq impersonate client (uses webpki-roots → trusts public Internet)
//!     → tls.peet.ws
//!
//! That's why we do NOT call `inject_origin_ca_into_wreq()`: the fingerprint
//! echo service is on the public Internet and is trusted by wreq's default
//! roots.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

mod common;

use common::{Fixture, FixtureBuilder};
use roxy_proxy_lib::handler::FINGERPRINT_HEADER;
use serde_json::Value;

/// Expected JA4 prefix for Chrome 137. The prefix encodes TLS version (`t13`
/// for TLS 1.3) and standard browser positional bits. The full hash component
/// changes with extension content; we match on the protocol prefix only.
///
/// Bump this constant when:
///   - the wreq version pinned in workspace changes
///   - a new Chrome variant is added to `Profile`
///
/// To compute the expected value: run a real Chrome 137 against
/// `https://browserleaks.com/tls` and copy the JA4 prefix.
const CHROME_137_JA4_PREFIX: &str = "t13d";

/// Helper that builds a reqwest client wired through roxy and trusting the
/// roxy MITM CA. Unlike Ring 2 tests, we do NOT trust the fake-origin CA
/// because Ring 3 talks to a public service over the public Internet.
fn client(f: &Fixture) -> reqwest::Client {
    let proxy_url = format!("http://{}", f.roxy_addr);
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::https(&proxy_url).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(f.roxy_ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap()
}

#[tokio::test]
#[ignore = "requires public network"]
async fn chrome_137_smoke_via_peet() {
    let f = FixtureBuilder::new()
        .default_profile("chrome-137")
        .build()
        .await;
    let c = client(&f);

    let resp = c
        .get("https://tls.peet.ws/api/all")
        .send()
        .await
        .expect("upstream reachable");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let body = resp.text().await.expect("response body");
    let json: Value = serde_json::from_str(&body).expect("json response");
    let ja4 = json
        .get("tls")
        .and_then(|t| t.get("ja4"))
        .and_then(|v| v.as_str())
        .expect("response has tls.ja4");
    assert!(
        ja4.starts_with(CHROME_137_JA4_PREFIX),
        "expected JA4 starting with {CHROME_137_JA4_PREFIX}, got {ja4}"
    );
}

#[tokio::test]
#[ignore = "requires public network"]
async fn custom_profile_smoke_via_peet() {
    // A minimal custom profile distinct from any builtin. TLS 1.3-only here
    // since this is testing the public-internet path; tls.peet.ws supports
    // TLS 1.3 cleanly, so cipher-suite negotiation is straightforward.
    let dir = tempfile::tempdir().unwrap();
    let toml = r#"
name = "smoke-custom"

[tls]
alpn = ["h2", "http/1.1"]
cipher_suites = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
supported_versions = ["TLS1.3"]
signature_algorithms = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"]
supported_groups = ["X25519", "P-256", "P-384"]

[http2]
header_table_size = 4096
enable_push = false
initial_window_size = 65535
max_frame_size = 16384
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE"]
header_order = [":method", ":authority", ":scheme", ":path", "user-agent", "accept"]
"#;
    std::fs::write(dir.path().join("smoke-custom.toml"), toml).unwrap();

    let f = FixtureBuilder::new().profiles_dir(dir.path()).build().await;
    let c = client(&f);

    let resp = c
        .get("https://tls.peet.ws/api/all")
        .header(FINGERPRINT_HEADER, "smoke-custom")
        .send()
        .await
        .expect("upstream reachable");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let body = resp.text().await.expect("response body");
    let json: Value = serde_json::from_str(&body).expect("json response");
    let ja4 = json
        .get("tls")
        .and_then(|t| t.get("ja4"))
        .and_then(|v| v.as_str())
        .expect("response has tls.ja4");
    // Custom profile uses TLS 1.3, so JA4 should start with `t13`.
    assert!(ja4.starts_with("t13"), "expected TLS1.3 JA4, got {ja4}");

    // Keep the tempdir alive for the lifetime of the fixture.
    drop(dir);
}
