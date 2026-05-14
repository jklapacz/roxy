#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end test for the capture server.
//!
//! Starts `roxy_capture::run` with a throwaway MITM CA, drives it with a real
//! `wreq` browser emulation (Chrome 137 — a genuine BoringSSL ClientHello with
//! GREASE, plus an HTTP/2 connection), and asserts the captured profile both
//! lands on disk and round-trips back through `roxy-impersonate`'s loader.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use roxy_mitm::{Ca, LeafSigner, SniResolver, Terminator};

#[tokio::test]
async fn captures_real_browser_fingerprint_into_loadable_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let ca_dir = tmp.path().join("ca");
    let profiles_dir = tmp.path().join("profiles");
    std::fs::create_dir_all(&ca_dir).unwrap();

    let ca = Ca::load_or_create(&ca_dir).unwrap();
    let signer = LeafSigner::new(ca);
    let resolver = Arc::new(SniResolver::new(signer, NonZeroUsize::new(16).unwrap()));
    let terminator = Terminator::new(resolver);

    // Reserve an ephemeral port, then hand it to the capture server.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let server_dir = profiles_dir.clone();
    tokio::spawn(async move {
        roxy_capture::run(addr, terminator, server_dir)
            .await
            .unwrap();
    });

    let client = wreq::Client::builder()
        .emulation(wreq_util::Emulation::Chrome137)
        .cert_verification(false)
        .build()
        .unwrap();

    let url = format!("https://localhost:{}/?name=test-capture", addr.port());

    // The server task needs a moment to bind; retry briefly.
    let mut last_err = None;
    let mut body = None;
    for _ in 0..40 {
        match client.get(&url).send().await {
            Ok(resp) => {
                assert_eq!(resp.status(), 200);
                body = Some(resp.text().await.unwrap());
                break;
            }
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let body = body.unwrap_or_else(|| panic!("capture server never responded: {last_err:?}"));
    assert!(body.contains("[tls]"), "response body:\n{body}");
    assert!(body.contains("[http2]"), "response body:\n{body}");
    assert!(
        body.contains(r#"name = "test-capture""#),
        "response body:\n{body}"
    );

    let path = profiles_dir.join("test-capture.toml");
    assert!(path.exists(), "captured profile file was not written");

    let profile = roxy_impersonate::CustomProfile::load(&path)
        .expect("captured profile must load via the custom-profile loader");
    assert_eq!(profile.spec.name, "test-capture");
    assert!(
        !profile.spec.tls.cipher_suites.is_empty(),
        "captured cipher_suites should not be empty"
    );
    assert!(
        !profile.spec.tls.supported_groups.is_empty(),
        "captured supported_groups should not be empty"
    );
    // Chrome emulation negotiates HTTP/2, so the http2 block must be real
    // (the loader rejects empty settings_order / header_order).
    assert!(!profile.spec.http2.settings_order.is_empty());
    assert!(profile
        .spec
        .http2
        .header_order
        .iter()
        .any(|h| h.starts_with(':')));

    // wreq's Chrome 137 emulation GREASEs, sends modern curves and ALPS, and
    // permutes its extension order — the enriched capture must record those.
    assert_eq!(
        profile.spec.tls.grease,
        Some(true),
        "GREASE should be detected"
    );
    assert_eq!(
        profile.spec.tls.permute_extensions,
        Some(true),
        "GREASE client should get permute_extensions best-guess"
    );
    assert!(
        profile.spec.tls.extension_permutation.is_empty(),
        "permuting client must not also pin extension_permutation"
    );
    assert!(
        !profile.spec.tls.alps_protocols.is_empty(),
        "ALPS protocols should be captured"
    );
}
