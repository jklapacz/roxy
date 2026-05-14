//! Parse a raw TLS ClientHello into the fields roxy's custom-profile schema
//! records.
//!
//! This is the inverse of `roxy-impersonate`'s `custom.rs`: where that module
//! translates string identifiers (`"server_name"`, `"ecdsa_secp256r1_sha256"`,
//! …) into typed wreq/BoringSSL values, this module turns the numeric values on
//! the wire back into exactly those strings. The mappings here MUST stay in
//! sync with `extension_from_str` / `tls_version_from_str` etc. in `custom.rs`,
//! or a captured profile will fail to load.
//!
//! GREASE values (RFC 8701) are filtered from every list — they are random
//! placeholders, not part of a replayable fingerprint.
//!
//! Numeric values with no roxy identifier are dropped and recorded in
//! `skipped_*` so the generated TOML can flag the capture as partial.

use anyhow::Context;
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, TlsCipherSuite, TlsExtension,
    TlsExtensionType, TlsMessage, TlsMessageHandshake,
};

/// The subset of a ClientHello that maps onto `roxy-impersonate`'s `TlsSpec`.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedTls {
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<String>,
    /// Ordered list of recognized extension identifiers from the ClientHello.
    /// Fed into `extension_permutation` by `render`, but only for non-GREASE
    /// clients (GREASE clients use `permute_extensions = true` instead).
    pub extensions: Vec<String>,
    pub supported_versions: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub supported_groups: Vec<String>,
    pub skipped_curves: Vec<u16>,
    /// Extension type numbers seen on the wire that have no roxy identifier.
    pub skipped_extensions: Vec<u16>,
    /// Cipher suite ids seen on the wire that `tls-parser` could not name.
    pub skipped_ciphers: Vec<u16>,
    /// Whether any GREASE value was observed in the ClientHello.
    pub grease: bool,
    /// status_request extension present → OCSP stapling requested.
    pub enable_ocsp_stapling: bool,
    /// signed_certificate_timestamp extension present.
    pub enable_signed_cert_timestamps: bool,
    /// encrypted_client_hello (0xfe0d) extension present.
    pub enable_ech_grease: bool,
    /// session_ticket extension present.
    pub session_ticket: bool,
    /// renegotiation_info extension present.
    pub renegotiation: bool,
    /// record_size_limit extension value, if present.
    pub record_size_limit: Option<u16>,
    /// pre_shared_key extension observed on the wire. `render` uses this together
    /// with `grease` to decide whether to emit a plain `pre_shared_key = true`
    /// (observed directly) or a guessed one with an inline comment.
    pub pre_shared_key_seen: bool,
    /// Protocols advertised in the ALPS (application_settings) extension.
    pub alps_protocols: Vec<String>,
    /// True when ALPS was signalled via the new codepoint (17613) rather than the original (17513).
    pub alps_use_new_codepoint: bool,
    /// Compression algorithm names from the compress_certificate extension.
    pub cert_compression: Vec<String>,
}

/// Parse the first TLS record in `record` as a ClientHello.
pub fn parse(record: &[u8]) -> anyhow::Result<CapturedTls> {
    let (_, plaintext) =
        parse_tls_plaintext(record).map_err(|e| anyhow::anyhow!("parse TLS record: {e:?}"))?;
    let ch = plaintext
        .msg
        .iter()
        .find_map(|m| match m {
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => Some(ch),
            _ => None,
        })
        .context("first TLS record is not a ClientHello")?;

    let mut grease = false;
    let mut cipher_suites = Vec::new();
    let mut skipped_ciphers = Vec::new();
    for c in &ch.ciphers {
        let id = c.0;
        if is_grease(id) {
            grease = true;
            continue;
        }
        match TlsCipherSuite::from_id(id) {
            Some(cs) => cipher_suites.push(cs.name.to_string()),
            None => skipped_ciphers.push(id),
        }
    }

    let mut extensions = Vec::new();
    let mut skipped_extensions = Vec::new();
    let mut supported_versions = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut alpn = Vec::new();
    let mut supported_groups = Vec::new();
    let mut skipped_curves = Vec::new();
    // --- TLS feature toggles ---
    let mut enable_ocsp_stapling = false;
    let mut enable_signed_cert_timestamps = false;
    let mut enable_ech_grease = false;
    let mut session_ticket = false;
    let mut renegotiation = false;
    let mut record_size_limit: Option<u16> = None;
    let mut pre_shared_key_seen = false;
    // --- ALPS / cert-compression ---
    let mut alps_protocols: Vec<String> = Vec::new();
    let mut alps_use_new_codepoint = false;
    let mut cert_compression: Vec<String> = Vec::new();

    if let Some(ext_bytes) = ch.ext {
        let (_, exts) = parse_tls_client_hello_extensions(ext_bytes)
            .map_err(|e| anyhow::anyhow!("parse ClientHello extensions: {e:?}"))?;
        for ext in &exts {
            // GREASE extension: a random placeholder type, never replayed.
            if matches!(ext, TlsExtension::Grease(..)) {
                grease = true;
                continue;
            }
            let ty: u16 = TlsExtensionType::from(ext).0;
            if ty == 65037 {
                enable_ech_grease = true;
            }
            match ty {
                17513 => alps_protocols = parse_alpn_list(unknown_data(ext)),
                17613 => {
                    alps_protocols = parse_alpn_list(unknown_data(ext));
                    alps_use_new_codepoint = true;
                }
                27 => cert_compression = parse_cert_compression(unknown_data(ext)),
                _ => {}
            }
            match extension_name(ty) {
                Some(name) => extensions.push(name.to_string()),
                None => skipped_extensions.push(ty),
            }
            match ext {
                TlsExtension::SupportedVersions(versions) => {
                    for v in versions {
                        if is_grease(v.0) {
                            grease = true;
                            continue;
                        }
                        if let Some(name) = tls_version_name(v.0) {
                            supported_versions.push(name.to_string());
                        }
                    }
                }
                TlsExtension::SignatureAlgorithms(algs) => {
                    for a in algs {
                        if is_grease(*a) {
                            grease = true;
                            continue;
                        }
                        if let Some(name) = sigalg_name(*a) {
                            signature_algorithms.push(name.to_string());
                        }
                    }
                }
                TlsExtension::ALPN(protocols) => {
                    for p in protocols {
                        if let Ok(s) = std::str::from_utf8(p) {
                            alpn.push(s.to_string());
                        }
                    }
                }
                TlsExtension::EllipticCurves(groups) => {
                    for g in groups {
                        if is_grease(g.0) {
                            grease = true;
                            continue;
                        }
                        match curve_name(g.0) {
                            Some(name) => supported_groups.push(name.to_string()),
                            None => skipped_curves.push(g.0),
                        }
                    }
                }
                TlsExtension::StatusRequest(_) => enable_ocsp_stapling = true,
                TlsExtension::SignedCertificateTimestamp(_) => enable_signed_cert_timestamps = true,
                TlsExtension::SessionTicket(_) => session_ticket = true,
                TlsExtension::RenegotiationInfo(_) => renegotiation = true,
                TlsExtension::PreSharedKey(_) => pre_shared_key_seen = true,
                TlsExtension::RecordSizeLimit(v) => record_size_limit = Some(*v),
                _ => {}
            }
        }
    }

    Ok(CapturedTls {
        alpn,
        cipher_suites,
        extensions,
        supported_versions,
        signature_algorithms,
        supported_groups,
        skipped_curves,
        skipped_extensions,
        skipped_ciphers,
        grease,
        enable_ocsp_stapling,
        enable_signed_cert_timestamps,
        enable_ech_grease,
        session_ticket,
        renegotiation,
        record_size_limit,
        pre_shared_key_seen,
        alps_protocols,
        alps_use_new_codepoint,
        cert_compression,
    })
}

/// RFC 8701 GREASE values: both bytes equal and of the form `0x?A`.
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0x00ff)
}

/// Named-group number → wreq `curves_list` identifier.
fn curve_name(group: u16) -> Option<&'static str> {
    Some(match group {
        23 => "P-256",
        24 => "P-384",
        25 => "P-521",
        29 => "X25519",
        4587 => "X25519Kyber768Draft00",
        4588 => "X25519MLKEM768",
        _ => return None,
    })
}

/// Extension type number → the lowercase identifier `custom.rs`'s
/// `extension_from_str` accepts. Only well-established types are listed;
/// anything else is reported as skipped rather than guessed.
fn extension_name(ty: u16) -> Option<&'static str> {
    Some(match ty {
        0 => "server_name",
        5 => "status_request",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        16 => "application_layer_protocol_negotiation",
        18 => "certificate_timestamp",
        21 => "padding",
        23 => "extended_master_secret",
        27 => "cert_compression",
        28 => "record_size_limit",
        34 => "delegated_credential",
        35 => "session_ticket",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        44 => "cookie",
        45 => "psk_key_exchange_modes",
        47 => "certificate_authorities",
        50 => "signature_algorithms_cert",
        51 => "key_share",
        17513 => "application_settings",
        17613 => "application_settings_new",
        65037 => "encrypted_client_hello",
        65281 => "renegotiation_info",
        _ => return None,
    })
}

/// TLS version number → `custom.rs`'s `tls_version_from_str` identifier.
fn tls_version_name(v: u16) -> Option<&'static str> {
    Some(match v {
        0x0301 => "TLS1.0",
        0x0302 => "TLS1.1",
        0x0303 => "TLS1.2",
        0x0304 => "TLS1.3",
        _ => return None,
    })
}

/// Signature scheme number → lowercase IETF name (wreq's `sigalgs_list`).
fn sigalg_name(v: u16) -> Option<&'static str> {
    Some(match v {
        0x0201 => "rsa_pkcs1_sha1",
        0x0203 => "ecdsa_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        0x0808 => "ed448",
        0x0809 => "rsa_pss_pss_sha256",
        0x080a => "rsa_pss_pss_sha384",
        0x080b => "rsa_pss_pss_sha512",
        _ => return None,
    })
}

/// Parse an ALPN-style protocol list: 2-byte list length, then a sequence of
/// (1-byte length, protocol bytes). Used for ALPS extension data (same wire shape as ALPN).
fn parse_alpn_list(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if data.len() < 2 {
        return out;
    }
    let mut i = 2; // skip the 2-byte list length
    while i < data.len() {
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&data[i..i + len]) {
            out.push(s.to_string());
        }
        i += len;
    }
    out
}

/// Parse `compress_certificate` (RFC 8879) data: 1-byte algorithm-bytes length
/// (skipped — we read to end-of-buffer), then 2-byte algorithm ids.
/// `1 → zlib`, `2 → brotli`, `3 → zstd`.
fn parse_cert_compression(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if data.is_empty() {
        return out;
    }
    let mut i = 1; // skip the 1-byte length
    while i + 1 < data.len() {
        let alg = u16::from_be_bytes([data[i], data[i + 1]]);
        i += 2;
        let name = match alg {
            1 => "zlib",
            2 => "brotli",
            3 => "zstd",
            _ => continue,
        };
        out.push(name.to_string());
    }
    out
}

/// Raw extension payload for a `TlsExtension::Unknown`; empty slice for typed
/// variants. Callers must only pass `Unknown` variants — the `debug_assert`
/// catches misuse in debug builds.
fn unknown_data<'a>(ext: &'a TlsExtension) -> &'a [u8] {
    match ext {
        TlsExtension::Unknown(_, data) => data,
        _ => {
            debug_assert!(false, "unknown_data called on typed variant");
            &[]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_values_detected() {
        for g in [
            0x0a0au16, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
            0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ] {
            assert!(is_grease(g), "{g:#06x} should be GREASE");
        }
    }

    #[test]
    fn non_grease_values_not_detected() {
        for v in [
            0x0000u16, 0x1301, 0x0403, 0x0304, 0x002b, 0x1a2a, 0x0a1a, 0xabab,
        ] {
            assert!(!is_grease(v), "{v:#06x} should not be GREASE");
        }
    }

    #[test]
    fn parses_alps_protocol_list() {
        // ALPS data: 2-byte list length, then [1-byte len + bytes]...
        let data = [0x00, 0x03, 0x02, b'h', b'2'];
        assert_eq!(parse_alpn_list(&data), vec!["h2".to_string()]);
    }

    #[test]
    fn parses_cert_compression_algorithms() {
        // compress_certificate data: 1-byte count-of-bytes, then 2-byte alg ids.
        let data = [0x02, 0x00, 0x02];
        assert_eq!(parse_cert_compression(&data), vec!["brotli".to_string()]);
    }

    #[test]
    fn alpn_list_handles_malformed_input() {
        // Too short to contain the 2-byte list-length prefix.
        assert!(parse_alpn_list(&[]).is_empty());
        assert!(parse_alpn_list(&[0x00]).is_empty());
        // Declared protocol length (16) runs past the buffer → break, no panic.
        assert!(parse_alpn_list(&[0x00, 0x05, 0x10, b'h', b'2']).is_empty());
    }

    #[test]
    fn cert_compression_handles_malformed_input() {
        assert!(parse_cert_compression(&[]).is_empty());
        // Only the length byte, no algorithm bytes → empty, no panic.
        assert!(parse_cert_compression(&[0x04]).is_empty());
        // Declared 4 bytes but only one 2-byte id follows → reads zlib, no panic.
        assert_eq!(
            parse_cert_compression(&[0x04, 0x00, 0x01]),
            vec!["zlib".to_string()]
        );
    }

    #[test]
    fn mappings_match_custom_loader_identifiers() {
        assert_eq!(extension_name(0), Some("server_name"));
        assert_eq!(extension_name(43), Some("supported_versions"));
        assert_eq!(extension_name(51), Some("key_share"));
        assert_eq!(extension_name(9999), None);
        assert_eq!(tls_version_name(0x0304), Some("TLS1.3"));
        assert_eq!(tls_version_name(0x0303), Some("TLS1.2"));
        assert_eq!(sigalg_name(0x0403), Some("ecdsa_secp256r1_sha256"));
        assert_eq!(sigalg_name(0x0804), Some("rsa_pss_rsae_sha256"));
        assert_eq!(sigalg_name(0xffff), None);
    }
}
