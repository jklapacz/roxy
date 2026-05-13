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
//! - `tls.extensions`: lowercase identifiers matching `boring2::ssl::ExtensionType`
//!   constants (e.g. `"server_name"`, `"supported_groups"`). Translated to
//!   typed `wreq::tls::ExtensionType` values here.
//! - `tls.supported_versions`: dotted SemVer-ish strings — `"TLS1.3"`, `"TLS1.2"`,
//!   `"TLS1.1"`, `"TLS1.0"`. The ORDERED list is interpreted by selecting the
//!   max as the upper bound and the min as the lower bound; wreq does not
//!   accept an ordered version list directly.
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
//!   HTTP/2 pseudo-header order and are silently ignored.

use crate::error::ImpersonateError;
use serde::Deserialize;
use std::path::Path;
use wreq::http2::{Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder};
use wreq::tls::{AlpnProtocol, ExtensionType, TlsOptions, TlsVersion};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CustomProfileSpec {
    pub name: String,
    pub tls: TlsSpec,
    pub http2: Http2Spec,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsSpec {
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<String>,
    pub extensions: Vec<String>,
    pub supported_versions: Vec<String>,
    pub signature_algorithms: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Http2Spec {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub settings_order: Vec<String>,
    pub header_order: Vec<String>,
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
        Ok(Self { spec, emulation })
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
    if spec.tls.cipher_suites.is_empty() {
        anyhow::bail!("tls.cipher_suites must not be empty");
    }
    if spec.tls.extensions.is_empty() {
        anyhow::bail!("tls.extensions must not be empty");
    }
    if spec.http2.settings_order.is_empty() {
        anyhow::bail!("http2.settings_order must not be empty");
    }
    if spec.http2.header_order.is_empty() {
        anyhow::bail!("http2.header_order must not be empty");
    }

    // ALPN translation.
    let alpn: Vec<AlpnProtocol> = spec
        .tls
        .alpn
        .iter()
        .map(|s| match s.as_str() {
            "h2" => Ok(AlpnProtocol::HTTP2),
            "http/1.1" => Ok(AlpnProtocol::HTTP1),
            "h3" => Ok(AlpnProtocol::HTTP3),
            other => Err(anyhow::anyhow!("unknown alpn protocol: {other}")),
        })
        .collect::<Result<_, _>>()?;

    // Extensions: typed list, ordered.
    let extensions: Vec<ExtensionType> = spec
        .tls
        .extensions
        .iter()
        .map(|s| extension_from_str(s))
        .collect::<Result<_, _>>()?;

    // Supported versions: wreq accepts min/max bounds. The spec gives an
    // ordered list (e.g. `["TLS1.3", "TLS1.2"]`); we pick the min/max of the
    // parsed values rather than honoring order, because wreq has no ordered
    // version-list knob.
    let parsed_versions: Vec<TlsVersion> = spec
        .tls
        .supported_versions
        .iter()
        .map(|s| tls_version_from_str(s))
        .collect::<Result<_, _>>()?;
    let (min_v, max_v) = if parsed_versions.is_empty() {
        (None, None)
    } else {
        let by_rank = |v: &TlsVersion| tls_version_rank(*v);
        let mut sorted = parsed_versions.clone();
        sorted.sort_by_key(by_rank);
        (sorted.first().copied(), sorted.last().copied())
    };

    // Cipher list: BoringSSL parses a colon-separated mini-language string.
    // We hand the user-supplied IANA names through verbatim; BoringSSL accepts
    // standard IANA names like `TLS_AES_128_GCM_SHA256`. Errors surface at
    // connection time, not load time — same behavior as the wreq-util builtin
    // profiles.
    let cipher_list = spec.tls.cipher_suites.join(":");

    // Signature algorithms: same colon-separated convention.
    let sigalgs_list = spec.tls.signature_algorithms.join(":");

    let mut tls_builder = TlsOptions::builder()
        .alpn_protocols(alpn)
        .extension_permutation(extensions)
        .cipher_list(cipher_list)
        .preserve_tls13_cipher_list(true);
    if !sigalgs_list.is_empty() {
        tls_builder = tls_builder.sigalgs_list(sigalgs_list);
    }
    if let Some(min) = min_v {
        tls_builder = tls_builder.min_tls_version(min);
    }
    if let Some(max) = max_v {
        tls_builder = tls_builder.max_tls_version(max);
    }
    let tls_options = tls_builder.build();

    // HTTP/2 settings order: typed builder.
    let mut settings_builder = SettingsOrder::builder();
    for s in &spec.http2.settings_order {
        let id = setting_from_str(s)?;
        settings_builder = settings_builder.push(id);
    }
    let settings_order = settings_builder.build();

    // HTTP/2 pseudo-header order: we ignore non-pseudo entries silently
    // (they're not part of the pseudo-header frame ordering). If a TOML lists
    // ONLY non-pseudo entries we error so the user gets feedback.
    let mut pseudo_builder = PseudoOrder::builder();
    let mut saw_pseudo = false;
    for s in &spec.http2.header_order {
        if let Some(id) = pseudo_from_str(s)? {
            pseudo_builder = pseudo_builder.push(id);
            saw_pseudo = true;
        }
    }
    if !saw_pseudo {
        anyhow::bail!(
            "http2.header_order contained no pseudo-headers (entries must start with ':' \
             and be one of :method, :scheme, :authority, :path, :protocol, :status)"
        );
    }
    let pseudo_order = pseudo_builder.build();

    let http2_options = Http2Options::builder()
        .header_table_size(spec.http2.header_table_size)
        .enable_push(spec.http2.enable_push)
        .initial_window_size(spec.http2.initial_window_size)
        .max_frame_size(spec.http2.max_frame_size)
        .max_header_list_size(spec.http2.max_header_list_size)
        .settings_order(settings_order)
        .headers_pseudo_order(pseudo_order)
        .build();

    Ok(wreq::Emulation::builder()
        .tls_options(tls_options)
        .http2_options(http2_options)
        .build())
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
/// `Ok(None)` and is silently dropped from the pseudo-header order.
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
extensions = ["server_name", "supported_groups"]
supported_versions = ["TLS1.3", "TLS1.2"]
signature_algorithms = ["ecdsa_secp256r1_sha256"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_frame_size = 16384
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
            spec.tls.extensions,
            vec!["server_name".to_string(), "supported_groups".to_string()]
        );
        assert_eq!(
            spec.tls.supported_versions,
            vec!["TLS1.3".to_string(), "TLS1.2".to_string()]
        );
        assert_eq!(spec.http2.header_table_size, 65536);
        assert!(!spec.http2.enable_push);
        assert_eq!(spec.http2.initial_window_size, 6291456);
        assert_eq!(spec.http2.max_frame_size, 16384);
        assert_eq!(spec.http2.max_header_list_size, 262144);
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
