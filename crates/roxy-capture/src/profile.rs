//! Render captured fingerprint data into a `roxy-impersonate` custom-profile
//! TOML and write it to the profiles directory.
//!
//! The emitter is hand-written (rather than `serde`) so the output can carry
//! explanatory comments and so it stays pinned to the exact schema that
//! `roxy-impersonate`'s `CustomProfileSpec` deserializes.

use crate::client_hello::CapturedTls;
use crate::h2::CapturedHttp2;
use roxy_impersonate::ProfileName;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Render a complete custom-profile TOML document.
pub fn render(
    name: &ProfileName,
    tls: &CapturedTls,
    http2: Option<&CapturedHttp2>,
    alpn: Option<&[u8]>,
) -> String {
    let mut out = String::new();
    out.push_str("# Captured by roxy-capture.\n");
    if let Some(a) = alpn {
        out.push_str(&format!(
            "# Negotiated ALPN: {}\n",
            String::from_utf8_lossy(a)
        ));
    }
    if !tls.skipped_extensions.is_empty() {
        out.push_str(&format!(
            "# NOTE: {} TLS extension(s) had no roxy identifier and were omitted: {}\n",
            tls.skipped_extensions.len(),
            join_nums(&tls.skipped_extensions),
        ));
    }
    if !tls.skipped_ciphers.is_empty() {
        out.push_str(&format!(
            "# NOTE: {} cipher suite(s) were unrecognized and omitted: {}\n",
            tls.skipped_ciphers.len(),
            tls.skipped_ciphers
                .iter()
                .map(|n| format!("0x{n:04x}"))
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    if !tls.skipped_curves.is_empty() {
        out.push_str(&format!(
            "# NOTE: {} named group(s) were unrecognized and omitted: {}\n",
            tls.skipped_curves.len(),
            tls.skipped_curves
                .iter()
                .map(|n| format!("0x{n:04x}"))
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    out.push('\n');
    out.push_str(&format!("name = {}\n\n", quote(name.as_str())));

    out.push_str("[tls]\n");
    out.push_str(&format!("alpn = {}\n", string_array(&tls.alpn)));
    out.push_str(&format!(
        "cipher_suites = {}\n",
        string_array(&tls.cipher_suites)
    ));
    out.push_str(&format!(
        "signature_algorithms = {}\n",
        string_array(&tls.signature_algorithms)
    ));
    out.push_str(&format!(
        "supported_versions = {}\n",
        string_array(&tls.supported_versions)
    ));
    out.push_str(&format!(
        "supported_groups = {}\n",
        string_array(&tls.supported_groups)
    ));
    if tls.grease {
        out.push_str("grease = true\n");
    }
    if tls.enable_ocsp_stapling {
        out.push_str("enable_ocsp_stapling = true\n");
    }
    if tls.enable_signed_cert_timestamps {
        out.push_str("enable_signed_cert_timestamps = true\n");
    }
    if tls.enable_ech_grease {
        out.push_str("enable_ech_grease = true\n");
    }
    if tls.session_ticket {
        out.push_str("session_ticket = true\n");
    }
    if tls.renegotiation {
        out.push_str("renegotiation = true\n");
    }
    if let Some(limit) = tls.record_size_limit {
        out.push_str(&format!("record_size_limit = {limit}\n"));
    }
    out.push('\n');

    out.push_str("[http2]\n");
    match http2 {
        Some(h) => {
            out.push_str(&format!("header_table_size = {}\n", h.header_table_size));
            out.push_str(&format!("enable_push = {}\n", h.enable_push));
            out.push_str(&format!(
                "initial_window_size = {}\n",
                h.initial_window_size
            ));
            out.push_str(&format!("max_frame_size = {}\n", h.max_frame_size));
            out.push_str(&format!(
                "max_header_list_size = {}\n",
                h.max_header_list_size
            ));
            out.push_str(&format!(
                "settings_order = {}\n",
                string_array(&h.settings_order)
            ));
            out.push_str(&format!(
                "header_order = {}\n",
                string_array(&h.header_order)
            ));
        }
        None => {
            out.push_str(
                "# WARNING: HTTP/2 was not captured (client negotiated HTTP/1.1).\n\
                 # The values below are Chrome-shaped defaults — verify before use.\n",
            );
            out.push_str("header_table_size = 65536\n");
            out.push_str("enable_push = false\n");
            out.push_str("initial_window_size = 6291456\n");
            out.push_str("max_header_list_size = 262144\n");
            out.push_str(
                "settings_order = [\"HEADER_TABLE_SIZE\", \"ENABLE_PUSH\", \
                 \"INITIAL_WINDOW_SIZE\", \"MAX_HEADER_LIST_SIZE\"]\n",
            );
            out.push_str("header_order = [\":method\", \":authority\", \":scheme\", \":path\"]\n");
        }
    }
    out
}

/// Write `toml` to `<dir>/<name>.toml`, creating `dir` if needed.
pub fn write_profile(dir: &Path, name: &ProfileName, toml: &str) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.toml", name.as_str()));
    let mut f = std::fs::File::create(&path)?;
    f.write_all(toml.as_bytes())?;
    Ok(path)
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn string_array(items: &[String]) -> String {
    let inner = items
        .iter()
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

fn join_nums(nums: &[u16]) -> String {
    nums.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tls() -> CapturedTls {
        CapturedTls {
            alpn: vec!["h2".into(), "http/1.1".into()],
            cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
            extensions: vec!["server_name".into(), "supported_groups".into()],
            supported_versions: vec!["TLS1.3".into(), "TLS1.2".into()],
            signature_algorithms: vec!["ecdsa_secp256r1_sha256".into()],
            supported_groups: vec!["X25519".into(), "P-256".into()],
            skipped_curves: vec![],
            skipped_extensions: vec![],
            skipped_ciphers: vec![],
            grease: false,
            enable_ocsp_stapling: false,
            enable_signed_cert_timestamps: false,
            enable_ech_grease: false,
            session_ticket: false,
            renegotiation: false,
            record_size_limit: None,
            pre_shared_key_seen: false,
        }
    }

    fn sample_http2() -> CapturedHttp2 {
        CapturedHttp2 {
            header_table_size: 65536,
            enable_push: false,
            initial_window_size: 6291456,
            max_frame_size: 16384,
            max_header_list_size: 262144,
            settings_order: vec!["HEADER_TABLE_SIZE".into(), "ENABLE_PUSH".into()],
            header_order: vec![":method".into(), ":authority".into()],
        }
    }

    /// The whole point of the hand-written emitter: its output must round-trip
    /// back through `roxy-impersonate`'s loader.
    #[test]
    fn rendered_profile_loads_back_through_custom_loader() {
        let name = ProfileName::parse("captured-test").unwrap();
        let toml = render(&name, &sample_tls(), Some(&sample_http2()), Some(b"h2"));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("captured-test.toml");
        std::fs::write(&path, &toml).unwrap();

        let profile = roxy_impersonate::CustomProfile::load(&path)
            .expect("rendered TOML must load via the custom-profile loader");
        assert_eq!(profile.spec.name, "captured-test");
        assert_eq!(
            profile.spec.tls.cipher_suites,
            vec!["TLS_AES_128_GCM_SHA256"]
        );
        assert_eq!(profile.spec.tls.supported_groups, vec!["X25519", "P-256"]);
    }

    #[test]
    fn http1_fallback_block_is_still_loadable() {
        let name = ProfileName::parse("captured-h1").unwrap();
        let toml = render(&name, &sample_tls(), None, Some(b"http/1.1"));
        assert!(toml.contains("WARNING: HTTP/2 was not captured"));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("captured-h1.toml");
        std::fs::write(&path, &toml).unwrap();
        roxy_impersonate::CustomProfile::load(&path)
            .expect("HTTP/1.1-fallback TOML must still load");
    }

    #[test]
    fn grease_true_emits_grease_field() {
        let name = ProfileName::parse("captured-grease").unwrap();
        let mut tls = sample_tls();
        tls.grease = true;
        let toml = render(&name, &tls, Some(&sample_http2()), Some(b"h2"));
        assert!(toml.contains("grease = true"), "toml:\n{toml}");
    }

    #[test]
    fn grease_false_omits_grease_field() {
        let name = ProfileName::parse("captured-no-grease").unwrap();
        let tls = sample_tls(); // grease: false
        let toml = render(&name, &tls, Some(&sample_http2()), Some(b"h2"));
        assert!(!toml.contains("grease ="), "toml:\n{toml}");
    }

    #[test]
    fn feature_toggles_emit_when_set() {
        let name = ProfileName::parse("captured-toggles").unwrap();
        let mut tls = sample_tls();
        tls.enable_ocsp_stapling = true;
        tls.enable_signed_cert_timestamps = true;
        tls.enable_ech_grease = true;
        tls.session_ticket = true;
        tls.renegotiation = true;
        tls.record_size_limit = Some(16385);
        let toml = render(&name, &tls, Some(&sample_http2()), Some(b"h2"));
        for needle in [
            "enable_ocsp_stapling = true",
            "enable_signed_cert_timestamps = true",
            "enable_ech_grease = true",
            "session_ticket = true",
            "renegotiation = true",
            "record_size_limit = 16385",
        ] {
            assert!(toml.contains(needle), "missing {needle} in:\n{toml}");
        }
    }

    #[test]
    fn write_profile_creates_dir_and_file() {
        let name = ProfileName::parse("written-profile").unwrap();
        let toml = render(&name, &sample_tls(), Some(&sample_http2()), None);
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("profiles");
        let path = write_profile(&nested, &name, &toml).unwrap();
        assert_eq!(path, nested.join("written-profile.toml"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), toml);
    }
}
