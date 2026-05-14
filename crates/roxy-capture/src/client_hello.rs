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
    pub extensions: Vec<String>,
    pub supported_versions: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub supported_groups: Vec<String>,
    pub skipped_curves: Vec<u16>,
    /// Extension type numbers seen on the wire that have no roxy identifier.
    pub skipped_extensions: Vec<u16>,
    /// Cipher suite ids seen on the wire that `tls-parser` could not name.
    pub skipped_ciphers: Vec<u16>,
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

    let mut cipher_suites = Vec::new();
    let mut skipped_ciphers = Vec::new();
    for c in &ch.ciphers {
        let id = c.0;
        if is_grease(id) {
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

    if let Some(ext_bytes) = ch.ext {
        let (_, exts) = parse_tls_client_hello_extensions(ext_bytes)
            .map_err(|e| anyhow::anyhow!("parse ClientHello extensions: {e:?}"))?;
        for ext in &exts {
            // GREASE extension: a random placeholder type, never replayed.
            if matches!(ext, TlsExtension::Grease(..)) {
                continue;
            }
            let ty: u16 = TlsExtensionType::from(ext).0;
            match extension_name(ty) {
                Some(name) => extensions.push(name.to_string()),
                None => skipped_extensions.push(ty),
            }
            match ext {
                TlsExtension::SupportedVersions(versions) => {
                    for v in versions {
                        if is_grease(v.0) {
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
                            continue;
                        }
                        match curve_name(g.0) {
                            Some(name) => supported_groups.push(name.to_string()),
                            None => skipped_curves.push(g.0),
                        }
                    }
                }
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
