//! Custom profile TOML loader.
//!
//! Parses a user-supplied TOML file into a `CustomProfileSpec` and translates
//! it into a `wreq::Emulation` (wreq's term for what the design doc and plan
//! call an "EmulationProvider"). The public TOML schema keeps every typed
//! identifier as a string; this module performs the string-to-wreq-enum
//! translation in one place and emits a clean error on unknowns.
//!
//! ## String identifier conventions
//!
//! - `tls.alpn`: lowercase wire names — `"h2"`, `"http/1.1"`.
//! - `tls.cipher_suites`: IANA names (e.g. `"TLS_AES_128_GCM_SHA256"`). Joined
//!   into a colon-separated BoringSSL cipher-list string and handed to wreq
//!   verbatim. wreq's underlying BoringSSL parses & validates them at
//!   connection time, not at load time.
//! - `tls.supported_groups`: named group identifiers (e.g. `"X25519"`, `"P-256"`).
//!   Joined into a colon-separated curves-list string for wreq's `curves_list`
//!   builder.
//! - `tls.extension_permutation`: lowercase identifiers matching
//!   `boring2::ssl::ExtensionType` constants (e.g. `"server_name"`). Translated
//!   to typed `wreq::tls::ExtensionType` values here.
//! - `tls.supported_versions`: dotted SemVer-ish strings — `"TLS1.3"`, `"TLS1.2"`,
//!   `"TLS1.1"`, `"TLS1.0"`. The ORDERED list is informational; only the min
//!   and max of this list are honored by wreq, and the load-time log confirms
//!   the resolved bounds. wreq does not accept an ordered version list
//!   directly.
//! - `tls.signature_algorithms`: lowercase IETF names (e.g.
//!   `"ecdsa_secp256r1_sha256"`). Joined into a colon-separated string for
//!   wreq's `sigalgs_list` builder.
//! - `http2.settings_order`: SCREAMING_SNAKE_CASE — `"HEADER_TABLE_SIZE"`,
//!   `"ENABLE_PUSH"`, `"MAX_CONCURRENT_STREAMS"`, `"INITIAL_WINDOW_SIZE"`,
//!   `"MAX_FRAME_SIZE"`, `"MAX_HEADER_LIST_SIZE"`, `"ENABLE_CONNECT_PROTOCOL"`,
//!   `"NO_RFC7540_PRIORITIES"`. Translated to `wreq::http2::SettingId`.
//! - `http2.header_order`: HTTP/2 pseudo-header names prefixed with `:`
//!   (e.g. `":method"`, `":authority"`, `":scheme"`, `":path"`). Translated
//!   to `wreq::http2::PseudoId`. Non-pseudo header names are not part of the
//!   HTTP/2 pseudo-header order and are dropped with a per-entry warning so
//!   operators copying header orders from packet captures see what was
//!   discarded.

use crate::error::ImpersonateError;
use serde::Deserialize;
use std::path::Path;
use wreq::http2::{
    Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId,
};
use wreq::tls::{
    AlpnProtocol, AlpsProtocol, CertificateCompressionAlgorithm, ExtensionType, TlsOptions,
    TlsVersion,
};

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CustomProfileSpec {
    pub name: String,
    pub tls: TlsSpec,
    pub http2: Http2Spec,
}

/// Mirrors the fingerprint-relevant subset of wreq's `TlsOptionsBuilder`.
/// Every field is optional: `build_emulation` calls a builder method only when
/// the field is present, so anything omitted falls through to wreq's default.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TlsSpec {
    // Core identity — required (validated in build_emulation).
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub supported_versions: Vec<String>,
    pub supported_groups: Vec<String>,
    // Feature toggles.
    pub grease: Option<bool>,
    pub permute_extensions: Option<bool>,
    pub aes_hw_override: Option<bool>,
    pub enable_ocsp_stapling: Option<bool>,
    pub enable_signed_cert_timestamps: Option<bool>,
    pub enable_ech_grease: Option<bool>,
    pub session_ticket: Option<bool>,
    pub renegotiation: Option<bool>,
    pub pre_shared_key: Option<bool>,
    pub psk_dhe_ke: Option<bool>,
    pub psk_skip_session_ticket: Option<bool>,
    pub preserve_tls13_cipher_list: Option<bool>,
    // Typed lists / values.
    pub alps_protocols: Vec<String>,
    pub alps_use_new_codepoint: Option<bool>,
    pub cert_compression: Vec<String>,
    pub delegated_credentials: Vec<String>,
    pub record_size_limit: Option<u16>,
    pub key_shares_limit: Option<u8>,
    /// Fixed extension order for non-permuting clients (Safari/okhttp). Mutually
    /// exclusive with `permute_extensions`.
    pub extension_permutation: Vec<String>,
}

/// Mirrors the fingerprint-relevant subset of wreq's `Http2OptionsBuilder`.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Http2Spec {
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub enable_connect_protocol: Option<bool>,
    pub no_rfc7540_priorities: Option<bool>,
    // Required (validated in build_emulation).
    pub settings_order: Vec<String>,
    pub header_order: Vec<String>,
    pub headers_stream_dependency: Option<HeadersStreamDependency>,
}

/// Priority info carried on the first HEADERS frame.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HeadersStreamDependency {
    pub stream_id: u32,
    /// Raw wire weight byte (0–255). HTTP/2 displays this as `weight + 1`.
    pub weight: u8,
    pub exclusive: bool,
}

/// A parsed + validated custom profile, ready to be plugged into wreq.
///
/// `emulation` is wreq's term for what the design doc calls an
/// "EmulationProvider". They are the same shape; wreq just spells it
/// `Emulation`.
#[derive(Debug)]
pub struct CustomProfile {
    pub spec: CustomProfileSpec,
    pub emulation: wreq::Emulation,
    /// Path the spec was loaded from, when applicable. `None` for
    /// programmatic construction (no file source); always `Some(...)` for
    /// profiles produced by `CustomProfile::load`/`load_dir`.
    pub source_path: Option<std::path::PathBuf>,
}

impl CustomProfile {
    pub fn load(path: &Path) -> Result<Self, ImpersonateError> {
        let text = std::fs::read_to_string(path).map_err(|e| ImpersonateError::CustomLoad {
            path: path.to_path_buf(),
            source: anyhow::anyhow!("read: {e}"),
        })?;
        let spec: CustomProfileSpec =
            toml::from_str(&text).map_err(|e| ImpersonateError::CustomLoad {
                path: path.to_path_buf(),
                source: anyhow::anyhow!("parse: {e}"),
            })?;
        crate::profile::ProfileName::parse(&spec.name).map_err(|e| {
            ImpersonateError::CustomLoad {
                path: path.to_path_buf(),
                source: anyhow::anyhow!("invalid name {:?}: {e}", spec.name),
            }
        })?;

        let emulation = build_emulation(&spec).map_err(|e| ImpersonateError::CustomLoad {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(Self {
            spec,
            emulation,
            source_path: Some(path.to_path_buf()),
        })
    }

    pub fn load_dir(dir: &Path) -> Result<Vec<CustomProfile>, ImpersonateError> {
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        let read = std::fs::read_dir(dir).map_err(|e| ImpersonateError::CustomLoad {
            path: dir.to_path_buf(),
            source: anyhow::anyhow!("readdir: {e}"),
        })?;
        for entry in read {
            let entry = entry.map_err(|e| ImpersonateError::CustomLoad {
                path: dir.to_path_buf(),
                source: anyhow::anyhow!("entry: {e}"),
            })?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            out.push(CustomProfile::load(&path)?);
        }
        Ok(out)
    }
}

fn build_emulation(spec: &CustomProfileSpec) -> Result<wreq::Emulation, anyhow::Error> {
    let tls = &spec.tls;
    let http2 = &spec.http2;

    // ----- validation: core identity must be present -----
    if tls.cipher_suites.is_empty() {
        anyhow::bail!("tls.cipher_suites must not be empty");
    }
    if tls.signature_algorithms.is_empty() {
        anyhow::bail!("tls.signature_algorithms must not be empty");
    }
    if tls.supported_groups.is_empty() {
        anyhow::bail!("tls.supported_groups must not be empty");
    }
    if tls.alpn.is_empty() {
        anyhow::bail!("tls.alpn must not be empty");
    }
    if http2.settings_order.is_empty() {
        anyhow::bail!("http2.settings_order must not be empty");
    }
    if http2.header_order.is_empty() {
        anyhow::bail!("http2.header_order must not be empty");
    }

    // ----- TLS -----
    let alpn: Vec<AlpnProtocol> = tls
        .alpn
        .iter()
        .map(|s| alpn_from_str(s))
        .collect::<Result<_, _>>()?;

    let parsed_versions: Vec<TlsVersion> = tls
        .supported_versions
        .iter()
        .map(|s| tls_version_from_str(s))
        .collect::<Result<_, _>>()?;
    let (min_v, max_v) = version_bounds(&parsed_versions);
    tracing::info!(
        profile = %spec.name,
        min = ?min_v,
        max = ?max_v,
        "custom profile: tls version bounds resolved from supported_versions"
    );

    let mut tls_builder = TlsOptions::builder()
        .alpn_protocols(alpn)
        .cipher_list(tls.cipher_suites.join(":"))
        .sigalgs_list(tls.signature_algorithms.join(":"))
        .curves_list(tls.supported_groups.join(":"))
        .preserve_tls13_cipher_list(tls.preserve_tls13_cipher_list.unwrap_or(true));

    if let Some(v) = min_v {
        tls_builder = tls_builder.min_tls_version(v);
    }
    if let Some(v) = max_v {
        tls_builder = tls_builder.max_tls_version(v);
    }

    if let Some(b) = tls.grease {
        tls_builder = tls_builder.grease_enabled(b);
    }
    if let Some(b) = tls.permute_extensions {
        tls_builder = tls_builder.permute_extensions(b);
    }
    if let Some(b) = tls.aes_hw_override {
        tls_builder = tls_builder.aes_hw_override(b);
    }
    if let Some(b) = tls.enable_ocsp_stapling {
        tls_builder = tls_builder.enable_ocsp_stapling(b);
    }
    if let Some(b) = tls.enable_signed_cert_timestamps {
        tls_builder = tls_builder.enable_signed_cert_timestamps(b);
    }
    if let Some(b) = tls.enable_ech_grease {
        tls_builder = tls_builder.enable_ech_grease(b);
    }
    if let Some(b) = tls.session_ticket {
        tls_builder = tls_builder.session_ticket(b);
    }
    if let Some(b) = tls.renegotiation {
        tls_builder = tls_builder.renegotiation(b);
    }
    if let Some(b) = tls.pre_shared_key {
        tls_builder = tls_builder.pre_shared_key(b);
    }
    if let Some(b) = tls.psk_dhe_ke {
        tls_builder = tls_builder.psk_dhe_ke(b);
    }
    if let Some(b) = tls.psk_skip_session_ticket {
        tls_builder = tls_builder.psk_skip_session_ticket(b);
    }
    if let Some(v) = tls.record_size_limit {
        tls_builder = tls_builder.record_size_limit(v);
    }
    if let Some(v) = tls.key_shares_limit {
        tls_builder = tls_builder.key_shares_limit(v);
    }

    if !tls.alps_protocols.is_empty() {
        let alps: Vec<AlpsProtocol> = tls
            .alps_protocols
            .iter()
            .map(|s| alps_from_str(s))
            .collect::<Result<_, _>>()?;
        tls_builder = tls_builder.alps_protocols(alps);
    }
    if let Some(b) = tls.alps_use_new_codepoint {
        tls_builder = tls_builder.alps_use_new_codepoint(b);
    }

    if !tls.cert_compression.is_empty() {
        let algs: Vec<CertificateCompressionAlgorithm> = tls
            .cert_compression
            .iter()
            .map(|s| cert_compression_from_str(s))
            .collect::<Result<_, _>>()?;
        tls_builder = tls_builder.certificate_compression_algorithms(algs);
    }

    if !tls.delegated_credentials.is_empty() {
        tls_builder = tls_builder.delegated_credentials(tls.delegated_credentials.join(":"));
    }

    if !tls.extension_permutation.is_empty() {
        if tls.permute_extensions == Some(true) {
            tracing::warn!(
                profile = %spec.name,
                "custom profile: both permute_extensions and extension_permutation set; \
                 permute_extensions wins, extension_permutation ignored"
            );
        } else {
            let exts: Vec<ExtensionType> = tls
                .extension_permutation
                .iter()
                .map(|s| extension_from_str(s))
                .collect::<Result<_, _>>()?;
            tls_builder = tls_builder.extension_permutation(exts);
        }
    }

    let tls_options = tls_builder.build();

    // ----- HTTP/2 -----
    let mut settings_builder = SettingsOrder::builder();
    for s in &http2.settings_order {
        settings_builder = settings_builder.push(setting_from_str(s)?);
    }
    let settings_order = settings_builder.build();

    let mut pseudo_builder = PseudoOrder::builder();
    let mut saw_pseudo = false;
    for entry in &http2.header_order {
        if let Some(id) = pseudo_from_str(entry)? {
            pseudo_builder = pseudo_builder.push(id);
            saw_pseudo = true;
        } else {
            tracing::warn!(
                profile = %spec.name,
                entry = %entry,
                "custom profile: dropping non-pseudo header_order entry",
            );
        }
    }
    if !saw_pseudo {
        anyhow::bail!(
            "http2.header_order contained no pseudo-headers (entries must start with ':' \
             and be one of :method, :scheme, :authority, :path, :protocol, :status)"
        );
    }
    let pseudo_order = pseudo_builder.build();

    let mut h2_builder = Http2Options::builder()
        .settings_order(settings_order)
        .headers_pseudo_order(pseudo_order);
    if let Some(v) = http2.header_table_size {
        h2_builder = h2_builder.header_table_size(v);
    }
    if let Some(b) = http2.enable_push {
        h2_builder = h2_builder.enable_push(b);
    }
    if let Some(v) = http2.max_concurrent_streams {
        h2_builder = h2_builder.max_concurrent_streams(v);
    }
    if let Some(v) = http2.initial_window_size {
        h2_builder = h2_builder.initial_window_size(v);
    }
    if let Some(v) = http2.initial_connection_window_size {
        h2_builder = h2_builder.initial_connection_window_size(v);
    }
    if let Some(v) = http2.max_frame_size {
        h2_builder = h2_builder.max_frame_size(v);
    }
    if let Some(v) = http2.max_header_list_size {
        h2_builder = h2_builder.max_header_list_size(v);
    }
    if let Some(b) = http2.enable_connect_protocol {
        h2_builder = h2_builder.enable_connect_protocol(b);
    }
    if let Some(b) = http2.no_rfc7540_priorities {
        h2_builder = h2_builder.no_rfc7540_priorities(b);
    }
    if let Some(dep) = &http2.headers_stream_dependency {
        h2_builder = h2_builder.headers_stream_dependency(StreamDependency::new(
            StreamId::from(dep.stream_id),
            dep.weight,
            dep.exclusive,
        ));
    }
    let http2_options = h2_builder.build();

    Ok(wreq::Emulation::builder()
        .tls_options(tls_options)
        .http2_options(http2_options)
        .build())
}

fn alpn_from_str(s: &str) -> Result<AlpnProtocol, anyhow::Error> {
    match s {
        "h2" => Ok(AlpnProtocol::HTTP2),
        "http/1.1" => Ok(AlpnProtocol::HTTP1),
        "h3" => Ok(AlpnProtocol::HTTP3),
        other => Err(anyhow::anyhow!("unknown alpn protocol: {other}")),
    }
}

fn alps_from_str(s: &str) -> Result<AlpsProtocol, anyhow::Error> {
    match s {
        "h2" => Ok(AlpsProtocol::HTTP2),
        "http/1.1" => Ok(AlpsProtocol::HTTP1),
        "h3" => Ok(AlpsProtocol::HTTP3),
        other => Err(anyhow::anyhow!("unknown alps protocol: {other}")),
    }
}

fn cert_compression_from_str(s: &str) -> Result<CertificateCompressionAlgorithm, anyhow::Error> {
    match s {
        "zlib" => Ok(CertificateCompressionAlgorithm::ZLIB),
        "brotli" => Ok(CertificateCompressionAlgorithm::BROTLI),
        "zstd" => Ok(CertificateCompressionAlgorithm::ZSTD),
        other => Err(anyhow::anyhow!(
            "unknown cert compression algorithm: {other}"
        )),
    }
}

/// Resolve the (min, max) TLS version bounds wreq accepts from the ordered
/// `supported_versions` list. Order is informational; wreq has no ordered knob.
fn version_bounds(versions: &[TlsVersion]) -> (Option<TlsVersion>, Option<TlsVersion>) {
    if versions.is_empty() {
        return (None, None);
    }
    let mut sorted = versions.to_vec();
    sorted.sort_by_key(|v| tls_version_rank(*v));
    (sorted.first().copied(), sorted.last().copied())
}

/// Translate a string identifier to a `wreq::tls::ExtensionType`.
/// Names match the `boring2::ssl::ExtensionType` constant names, lowercased.
fn extension_from_str(s: &str) -> Result<ExtensionType, anyhow::Error> {
    let ext = match s {
        "server_name" => ExtensionType::SERVER_NAME,
        "status_request" => ExtensionType::STATUS_REQUEST,
        "ec_point_formats" => ExtensionType::EC_POINT_FORMATS,
        "signature_algorithms" => ExtensionType::SIGNATURE_ALGORITHMS,
        "srtp" => ExtensionType::SRTP,
        "application_layer_protocol_negotiation" => {
            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        }
        "padding" => ExtensionType::PADDING,
        "extended_master_secret" => ExtensionType::EXTENDED_MASTER_SECRET,
        "quic_transport_parameters_legacy" => ExtensionType::QUIC_TRANSPORT_PARAMETERS_LEGACY,
        "quic_transport_parameters_standard" => ExtensionType::QUIC_TRANSPORT_PARAMETERS_STANDARD,
        "cert_compression" => ExtensionType::CERT_COMPRESSION,
        "session_ticket" => ExtensionType::SESSION_TICKET,
        "supported_groups" => ExtensionType::SUPPORTED_GROUPS,
        "pre_shared_key" => ExtensionType::PRE_SHARED_KEY,
        "early_data" => ExtensionType::EARLY_DATA,
        "supported_versions" => ExtensionType::SUPPORTED_VERSIONS,
        "cookie" => ExtensionType::COOKIE,
        "psk_key_exchange_modes" => ExtensionType::PSK_KEY_EXCHANGE_MODES,
        "certificate_authorities" => ExtensionType::CERTIFICATE_AUTHORITIES,
        "signature_algorithms_cert" => ExtensionType::SIGNATURE_ALGORITHMS_CERT,
        "key_share" => ExtensionType::KEY_SHARE,
        "renegotiate" => ExtensionType::RENEGOTIATE,
        "renegotiation_info" => ExtensionType::RENEGOTIATE,
        "delegated_credential" => ExtensionType::DELEGATED_CREDENTIAL,
        "application_settings" => ExtensionType::APPLICATION_SETTINGS,
        "application_settings_new" => ExtensionType::APPLICATION_SETTINGS_NEW,
        "encrypted_client_hello" => ExtensionType::ENCRYPTED_CLIENT_HELLO,
        "certificate_timestamp" => ExtensionType::CERTIFICATE_TIMESTAMP,
        "next_proto_neg" => ExtensionType::NEXT_PROTO_NEG,
        "channel_id" => ExtensionType::CHANNEL_ID,
        "record_size_limit" => ExtensionType::RECORD_SIZE_LIMIT,
        other => anyhow::bail!("unknown tls extension: {other}"),
    };
    Ok(ext)
}

fn tls_version_from_str(s: &str) -> Result<TlsVersion, anyhow::Error> {
    match s {
        "TLS1.0" => Ok(TlsVersion::TLS_1_0),
        "TLS1.1" => Ok(TlsVersion::TLS_1_1),
        "TLS1.2" => Ok(TlsVersion::TLS_1_2),
        "TLS1.3" => Ok(TlsVersion::TLS_1_3),
        other => Err(anyhow::anyhow!("unknown tls version: {other}")),
    }
}

fn tls_version_rank(v: TlsVersion) -> u8 {
    if v == TlsVersion::TLS_1_0 {
        0
    } else if v == TlsVersion::TLS_1_1 {
        1
    } else if v == TlsVersion::TLS_1_2 {
        2
    } else if v == TlsVersion::TLS_1_3 {
        3
    } else {
        u8::MAX
    }
}

fn setting_from_str(s: &str) -> Result<SettingId, anyhow::Error> {
    match s {
        "HEADER_TABLE_SIZE" => Ok(SettingId::HeaderTableSize),
        "ENABLE_PUSH" => Ok(SettingId::EnablePush),
        "MAX_CONCURRENT_STREAMS" => Ok(SettingId::MaxConcurrentStreams),
        "INITIAL_WINDOW_SIZE" => Ok(SettingId::InitialWindowSize),
        "MAX_FRAME_SIZE" => Ok(SettingId::MaxFrameSize),
        "MAX_HEADER_LIST_SIZE" => Ok(SettingId::MaxHeaderListSize),
        "ENABLE_CONNECT_PROTOCOL" => Ok(SettingId::EnableConnectProtocol),
        "NO_RFC7540_PRIORITIES" => Ok(SettingId::NoRfc7540Priorities),
        other => Err(anyhow::anyhow!("unknown http2 setting: {other}")),
    }
}

/// `:method` → `PseudoId::Method`, etc. Non-pseudo (no `:` prefix) returns
/// `Ok(None)`; the caller is responsible for warning the operator that the
/// entry was dropped (see `build_emulation`).
fn pseudo_from_str(s: &str) -> Result<Option<PseudoId>, anyhow::Error> {
    if !s.starts_with(':') {
        return Ok(None);
    }
    match s {
        ":method" => Ok(Some(PseudoId::Method)),
        ":scheme" => Ok(Some(PseudoId::Scheme)),
        ":authority" => Ok(Some(PseudoId::Authority)),
        ":path" => Ok(Some(PseudoId::Path)),
        ":protocol" => Ok(Some(PseudoId::Protocol)),
        ":status" => Ok(Some(PseudoId::Status)),
        other => Err(anyhow::anyhow!("unknown pseudo-header: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_TOML: &str = r#"
name = "chrome-148"

[tls]
alpn = ["h2", "http/1.1"]
cipher_suites = ["TLS_AES_128_GCM_SHA256"]
signature_algorithms = ["ecdsa_secp256r1_sha256"]
supported_versions = ["TLS1.3", "TLS1.2"]
supported_groups = ["X25519", "P-256"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH"]
header_order = [":method", ":authority", ":scheme", ":path"]
"#;

    #[test]
    fn parses_minimal_spec() {
        let spec: CustomProfileSpec = toml::from_str(MINIMAL_TOML).unwrap();
        assert_eq!(spec.name, "chrome-148");
        assert_eq!(
            spec.tls.alpn,
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
        assert_eq!(spec.tls.cipher_suites, vec!["TLS_AES_128_GCM_SHA256"]);
        assert_eq!(
            spec.tls.supported_groups,
            vec!["X25519".to_string(), "P-256".to_string()]
        );
        assert_eq!(
            spec.tls.supported_versions,
            vec!["TLS1.3".to_string(), "TLS1.2".to_string()]
        );
        assert_eq!(spec.http2.header_table_size, Some(65536));
        assert_eq!(spec.http2.enable_push, Some(false));
        assert_eq!(spec.http2.initial_window_size, Some(6291456));
        assert_eq!(spec.http2.max_header_list_size, Some(262144));
        assert_eq!(
            spec.http2.settings_order,
            vec!["HEADER_TABLE_SIZE".to_string(), "ENABLE_PUSH".to_string()]
        );
        assert_eq!(
            spec.http2.header_order,
            vec![
                ":method".to_string(),
                ":authority".to_string(),
                ":scheme".to_string(),
                ":path".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_invalid_name() {
        let bad = MINIMAL_TOML.replace(r#"name = "chrome-148""#, r#"name = "Chrome_148""#);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, bad).unwrap();
        match CustomProfile::load(&path) {
            Err(ImpersonateError::CustomLoad { source, .. }) => {
                let msg = format!("{source}");
                assert!(msg.contains("invalid name"), "got: {msg}");
            }
            other => panic!("expected CustomLoad, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_required_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noop.toml");
        std::fs::write(&path, r#"name = "x""#).unwrap();
        match CustomProfile::load(&path) {
            Err(ImpersonateError::CustomLoad { source, .. }) => {
                let msg = format!("{source}");
                assert!(msg.contains("parse"), "got: {msg}");
            }
            other => panic!("expected CustomLoad, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_alpn() {
        let bad = MINIMAL_TOML.replace(r#"alpn = ["h2", "http/1.1"]"#, r#"alpn = ["h5"]"#);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad-alpn.toml");
        std::fs::write(&path, bad).unwrap();
        match CustomProfile::load(&path) {
            Err(ImpersonateError::CustomLoad { source, .. }) => {
                let msg = format!("{source}");
                assert!(msg.contains("unknown alpn"), "got: {msg}");
            }
            other => panic!("expected CustomLoad, got {other:?}"),
        }
    }

    #[test]
    fn rejects_legacy_extensions_field() {
        let legacy = MINIMAL_TOML.replace(
            "supported_groups = [\"X25519\", \"P-256\"]",
            "supported_groups = [\"X25519\"]\nextensions = [\"server_name\"]",
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.toml");
        std::fs::write(&path, legacy).unwrap();
        match CustomProfile::load(&path) {
            Err(ImpersonateError::CustomLoad { source, .. }) => {
                let msg = format!("{source}");
                assert!(msg.contains("parse"), "got: {msg}");
            }
            other => panic!("expected CustomLoad parse error, got {other:?}"),
        }
    }

    #[test]
    fn load_dir_returns_empty_for_missing_dir() {
        let v =
            CustomProfile::load_dir(std::path::Path::new("/nonexistent-dir-roxy-tests")).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn load_dir_picks_up_toml_files() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("good.toml");
        std::fs::write(&toml_path, MINIMAL_TOML).unwrap();
        let other_path = dir.path().join("ignore.txt");
        std::fs::write(&other_path, "not toml").unwrap();
        let profiles = CustomProfile::load_dir(dir.path()).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].spec.name, "chrome-148");
    }
}
