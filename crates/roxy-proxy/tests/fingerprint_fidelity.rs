#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

//! Ring 3 fidelity gate: a known-good chrome-148 profile, replayed through
//! roxy, must reproduce real Chrome 148's JA4_r, peetprint, and HTTP/2 akamai
//! fingerprint — except for two TLS extensions roxy cannot reproduce on a cold
//! connection: extension 51764 (0xca34, no wreq knob) and 0x0029/41
//! (pre_shared_key, only sent on TLS 1.3 session resumption).
//!
//! `#[ignore]` because it requires public network access. Run with:
//!   cargo test -p roxy-proxy --test fingerprint_fidelity -- --ignored --nocapture

mod common;

use common::{Fixture, FixtureBuilder};
use roxy_proxy_lib::handler::FINGERPRINT_HEADER;
use serde_json::Value;

// To re-capture for a new Chrome version: visit https://tls.peet.ws/api/all in
// real Chrome and copy `.tls.ja4_r`, `.tls.peetprint`, and
// `.http2.akamai_fingerprint` from the JSON response.

/// JA4_r of real Chrome 148 against tls.peet.ws, recorded 2026-05-14.
const REAL_CHROME_148_JA4R: &str = "t13d1518h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,ca34,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601";

/// peetprint of real Chrome 148 against tls.peet.ws, recorded 2026-05-14.
const REAL_CHROME_148_PEETPRINT: &str = "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-41-43-45-5-51-51764-65037-65281-GREASE-GREASE";

/// HTTP/2 akamai fingerprint of real Chrome 148 against tls.peet.ws, recorded
/// 2026-05-14. Format: `SETTINGS|WINDOW_UPDATE|PRIORITY|HEADER_ORDER` — every
/// component is deterministic for Chrome (no per-connection randomness, no
/// TLS-side exclusions), so it is compared verbatim.
const REAL_CHROME_148_AKAMAI: &str = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p";

/// Known-good chrome-148 profile, derived from the real Chrome 148 ClientHello
/// + HTTP/2 reference capture in the design doc. New-schema format.
const CHROME_148_PROFILE: &str = r#"
name = "chrome-148"

[tls]
alpn = ["h2", "http/1.1"]
cipher_suites = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"]
signature_algorithms = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512"]
supported_versions = ["TLS1.3", "TLS1.2"]
supported_groups = ["X25519MLKEM768", "X25519", "P-256", "P-384"]
grease = true
permute_extensions = true
aes_hw_override = true
enable_ocsp_stapling = true
enable_signed_cert_timestamps = true
enable_ech_grease = true
session_ticket = true
renegotiation = true
pre_shared_key = true
alps_protocols = ["h2"]
alps_use_new_codepoint = true
cert_compression = ["brotli"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
# Target connection window: real Chrome's WINDOW_UPDATE wire increment
# (15663105) plus the RFC 9113 default window (65535). wreq emits
# `target - 65535` on the wire.
initial_connection_window_size = 15728640
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_HEADER_LIST_SIZE"]
header_order = [":method", ":authority", ":scheme", ":path"]

[http2.headers_stream_dependency]
stream_id = 0
weight = 255
exclusive = true
"#;

/// reqwest client wired through roxy, trusting the roxy MITM CA. Mirrors
/// `fingerprint_smoke.rs::client` — Ring 3 talks to the public Internet, so we
/// do NOT trust the fake-origin CA.
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
async fn captured_chrome_148_matches_real_ja4r_and_peetprint() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("chrome-148.toml"), CHROME_148_PROFILE).unwrap();

    let f = FixtureBuilder::new().profiles_dir(dir.path()).build().await;
    let c = client(&f);

    let resp = c
        .get("https://tls.peet.ws/api/all")
        .header(FINGERPRINT_HEADER, "chrome-148")
        .send()
        .await
        .expect("upstream reachable");
    assert!(resp.status().is_success(), "status: {}", resp.status());
    let json: Value = serde_json::from_str(&resp.text().await.unwrap()).expect("json response");
    let tls = json.get("tls").expect("response has tls section");
    let got_ja4r = tls
        .get("ja4_r")
        .and_then(|v| v.as_str())
        .expect("tls.ja4_r");
    let got_peet = tls
        .get("peetprint")
        .and_then(|v| v.as_str())
        .expect("tls.peetprint");

    // JA4_r = <ja4_a>_<ciphers>_<extensions>_<sigalgs>. Compare the cipher and
    // sigalg sections verbatim; compare the extension section after removing
    // two extensions roxy cannot reproduce on a cold connection:
    //   - 0xca34 (51764): no wreq knob exists for it.
    //   - 0x0029 (41, pre_shared_key): only appears on TLS 1.3 session
    //     resumption; a cold request has no cached ticket to offer, so neither
    //     roxy nor real Chrome would send it on a first visit. The reference
    //     was captured warm. (See design doc, decision 3.)
    let real: Vec<&str> = REAL_CHROME_148_JA4R.split('_').collect();
    let got: Vec<&str> = got_ja4r.split('_').collect();
    assert_eq!(got.len(), 4, "unexpected JA4_r shape: {got_ja4r}");
    assert_eq!(got[1], real[1], "JA4_r cipher section mismatch");
    assert_eq!(got[3], real[3], "JA4_r sigalg section mismatch");
    // Tokenize → filter → rejoin so the exclusion is position-independent
    // (a string `.replace` would silently no-op if an excluded token ever
    // landed at a list boundary in a future reference update).
    let cleaned_real_exts = real[2]
        .split(',')
        .filter(|t| *t != "ca34" && *t != "0029")
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        got[2], cleaned_real_exts,
        "JA4_r extension section mismatch (0xca34 and 0x0029/PSK excluded)"
    );

    // peetprint's final `|`-section is the sorted extension list; filter the
    // two excluded extensions from just that section, then rejoin.
    let cleaned_peet = {
        let (prefix, ext_section) = REAL_CHROME_148_PEETPRINT
            .rsplit_once('|')
            .expect("peetprint has pipe-delimited sections");
        let cleaned_ext = ext_section
            .split('-')
            .filter(|t| *t != "51764" && *t != "41")
            .collect::<Vec<_>>()
            .join("-");
        format!("{prefix}|{cleaned_ext}")
    };
    assert_eq!(
        got_peet, cleaned_peet,
        "peetprint mismatch (51764 and 41/PSK excluded)"
    );

    // HTTP/2 akamai fingerprint — every component is deterministic for Chrome,
    // so it is compared verbatim (this is what catches HTTP/2-layer drift such
    // as a wrong WINDOW_UPDATE increment).
    let got_akamai = json
        .get("http2")
        .and_then(|h| h.get("akamai_fingerprint"))
        .and_then(|v| v.as_str())
        .expect("http2.akamai_fingerprint");
    assert_eq!(
        got_akamai, REAL_CHROME_148_AKAMAI,
        "HTTP/2 akamai fingerprint mismatch"
    );
}
