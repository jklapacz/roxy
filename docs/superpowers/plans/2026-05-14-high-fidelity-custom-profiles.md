# High-Fidelity Custom Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a captured custom profile reproduce real Chrome's JA4_r and peetprint by reshaping `roxy-impersonate`'s `CustomProfileSpec` to mirror wreq's fingerprint-relevant builder surface, then enriching `roxy-capture`'s detection to fill it.

**Architecture:** `roxy-impersonate/src/custom.rs` holds the profile schema (`TlsSpec`/`Http2Spec`) and `build_emulation` (schema → `wreq::Emulation`). `roxy-capture` parses a real ClientHello + HTTP/2 frames into `CapturedTls`/`CapturedHttp2` and renders a TOML string that must round-trip through `CustomProfile::load`. The schema reshape is one atomic task (Task 1, both crates); subsequent tasks add one detectable field at a time.

**Tech Stack:** Rust, `wreq` 6.0.0-rc.28 (`TlsOptionsBuilder`/`Http2OptionsBuilder`), `tls-parser` 0.12, `httlib-hpack` 0.1.

**Reference spec:** `docs/superpowers/specs/2026-05-14-high-fidelity-custom-profiles-design.md`

---

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `crates/roxy-impersonate/src/custom.rs` | Profile schema structs + `build_emulation` + str→typed helpers | 1 |
| `crates/roxy-impersonate/src/client.rs` | `COLLIDING_SPEC` test fixture (schema update only) | 1 |
| `crates/roxy-proxy/tests/impersonate.rs` | inline custom-profile TOML fixture (schema update only) | 1 |
| `crates/roxy-proxy/tests/fingerprint_smoke.rs` | inline custom-profile TOML fixture (schema update only) | 1 |
| `crates/roxy-capture/src/client_hello.rs` | ClientHello → `CapturedTls` (curves, GREASE, toggles, ALPS, cert-compression) | 1–6 |
| `crates/roxy-capture/src/h2.rs` | HTTP/2 frames → `CapturedHttp2` (optional settings, window-update, priority) | 7–8 |
| `crates/roxy-capture/src/profile.rs` | `CapturedTls`/`CapturedHttp2` → new-schema TOML string | 1–8 |
| `crates/roxy-capture/tests/capture_e2e.rs` | end-to-end capture assertion | 1, 9 |
| `crates/roxy-proxy/tests/fingerprint_fidelity.rs` | NEW — ignored network test asserting JA4_r/peetprint match | 9 |

---

## Task 1: Schema migration (atomic, both crates)

Reshape `TlsSpec`/`Http2Spec` to all-optional fields mirroring wreq's builder surface, rewrite `build_emulation`, capture `supported_groups` (the one new *required* field), rewrite the TOML emitter, and update every inline TOML fixture. After this task the whole workspace compiles and all tests pass.

**Files:**
- Modify: `crates/roxy-impersonate/src/custom.rs`
- Modify: `crates/roxy-impersonate/src/client.rs` (`COLLIDING_SPEC` const, ~line 283)
- Modify: `crates/roxy-proxy/tests/impersonate.rs` (inline TOML, ~line 200)
- Modify: `crates/roxy-proxy/tests/fingerprint_smoke.rs` (inline TOML, ~line 90)
- Modify: `crates/roxy-capture/src/client_hello.rs`
- Modify: `crates/roxy-capture/src/profile.rs`
- Modify: `crates/roxy-capture/tests/capture_e2e.rs`

- [ ] **Step 1: Replace the schema structs in `custom.rs`**

Replace the current `CustomProfileSpec`, `TlsSpec`, `Http2Spec` definitions (lines ~44–69) with:

```rust
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
```

- [ ] **Step 2: Update the imports at the top of `custom.rs`**

Replace the two `use wreq::...` lines (~lines 41–42) with:

```rust
use wreq::http2::{
    Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId,
};
use wreq::tls::{
    AlpnProtocol, AlpsProtocol, CertificateCompressionAlgorithm, ExtensionType, TlsOptions,
    TlsVersion,
};
```

- [ ] **Step 3: Add the new str→typed helpers in `custom.rs`**

Add these functions next to the existing `extension_from_str` / `setting_from_str` family:

```rust
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
        other => Err(anyhow::anyhow!("unknown cert compression algorithm: {other}")),
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
```

- [ ] **Step 4: Rewrite `build_emulation` in `custom.rs`**

Replace the entire `build_emulation` function body with:

```rust
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
```

- [ ] **Step 5: Update `custom.rs` test fixtures and tests**

In the `#[cfg(test)] mod tests` block, replace `MINIMAL_TOML` with:

```rust
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
```

Then update the test bodies in that module:
- `parses_minimal_spec`: replace the `spec.tls.extensions` assertion with
  `assert_eq!(spec.tls.supported_groups, vec!["X25519".to_string(), "P-256".to_string()]);`
  and change `assert_eq!(spec.http2.header_table_size, 65536);` to
  `assert_eq!(spec.http2.header_table_size, Some(65536));` and
  `assert!(!spec.http2.enable_push);` to `assert_eq!(spec.http2.enable_push, Some(false));`
  and `assert_eq!(spec.http2.initial_window_size, 6291456);` to
  `assert_eq!(spec.http2.initial_window_size, Some(6291456));` and
  `assert_eq!(spec.http2.max_header_list_size, 262144);` to
  `assert_eq!(spec.http2.max_header_list_size, Some(262144));`. Remove the
  `spec.http2.max_frame_size` assertion entirely.
- `rejects_unknown_alpn`: unchanged (still valid).
- Add a new test:

```rust
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
```

- [ ] **Step 6: Update the `client.rs` `COLLIDING_SPEC` fixture**

In `crates/roxy-impersonate/src/client.rs`, replace the `COLLIDING_SPEC` const body (~line 283) with:

```rust
    pub const COLLIDING_SPEC: &str = r#"
name = "chrome-137"

[tls]
alpn = ["h2"]
cipher_suites = ["TLS_AES_128_GCM_SHA256"]
signature_algorithms = ["ecdsa_secp256r1_sha256"]
supported_versions = ["TLS1.3"]
supported_groups = ["X25519"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE"]
header_order = [":method"]
"#;
```

- [ ] **Step 7: Update the `roxy-proxy/tests/impersonate.rs` inline TOML**

In `crates/roxy-proxy/tests/impersonate.rs` (~line 200), replace the `[tls]`/`[http2]` body of the `test-custom` profile so it uses the new schema (drop `extensions`, add `supported_groups`):

```toml
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
signature_algorithms = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
]
supported_versions = ["TLS1.3", "TLS1.2"]
supported_groups = ["X25519", "P-256", "P-384"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE"]
header_order = [":method", ":authority", ":scheme", ":path"]
```

- [ ] **Step 8: Update the `roxy-proxy/tests/fingerprint_smoke.rs` inline TOML**

In `crates/roxy-proxy/tests/fingerprint_smoke.rs` (~line 90), in the `toml` raw string: remove the `extensions = [...]` line and add `supported_groups = ["X25519", "P-256", "P-384"]` in the `[tls]` block. Leave the rest of that fixture unchanged.

- [ ] **Step 9: Capture `supported_groups` in `client_hello.rs`**

In `crates/roxy-capture/src/client_hello.rs`, add a field to `CapturedTls`:

```rust
    pub supported_groups: Vec<String>,
    pub skipped_curves: Vec<u16>,
```

Add the curve-name table next to `extension_name`:

```rust
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
```

In `parse`, add local accumulators `let mut supported_groups = Vec::new();` and
`let mut skipped_curves = Vec::new();`, add this arm to the `match ext` block:

```rust
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
```

and add `supported_groups` and `skipped_curves` to the `CapturedTls { .. }` constructor at the end of `parse`.

- [ ] **Step 10: Rewrite `profile.rs::render` to emit the new schema**

In `crates/roxy-capture/src/profile.rs`, replace `render` so the `[tls]` and
`[http2]` blocks match the new schema. The Task-1 version emits only the fields
`CapturedTls`/`CapturedHttp2` currently carry:

```rust
pub fn render(
    name: &ProfileName,
    tls: &CapturedTls,
    http2: Option<&CapturedHttp2>,
    alpn: Option<&[u8]>,
) -> String {
    let mut out = String::new();
    out.push_str("# Captured by roxy-capture.\n");
    if let Some(a) = alpn {
        out.push_str(&format!("# Negotiated ALPN: {}\n", String::from_utf8_lossy(a)));
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
            join_nums(&tls.skipped_curves),
        ));
    }
    out.push('\n');
    out.push_str(&format!("name = {}\n\n", quote(name.as_str())));

    out.push_str("[tls]\n");
    out.push_str(&format!("alpn = {}\n", string_array(&tls.alpn)));
    out.push_str(&format!("cipher_suites = {}\n", string_array(&tls.cipher_suites)));
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
    out.push('\n');

    out.push_str("[http2]\n");
    match http2 {
        Some(h) => {
            out.push_str(&format!("header_table_size = {}\n", h.header_table_size));
            out.push_str(&format!("enable_push = {}\n", h.enable_push));
            out.push_str(&format!("initial_window_size = {}\n", h.initial_window_size));
            out.push_str(&format!("max_frame_size = {}\n", h.max_frame_size));
            out.push_str(&format!(
                "max_header_list_size = {}\n",
                h.max_header_list_size
            ));
            out.push_str(&format!(
                "settings_order = {}\n",
                string_array(&h.settings_order)
            ));
            out.push_str(&format!("header_order = {}\n", string_array(&h.header_order)));
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
```

(Note: `extensions` is no longer emitted. `CapturedTls.extensions` stays on the
struct — Task 5 repurposes it as `extension_permutation`.)

- [ ] **Step 11: Update `profile.rs` unit tests**

In `profile.rs`'s `#[cfg(test)] mod tests`:
- In `sample_tls()`, remove the `extensions` field initializer if `CapturedTls`
  no longer has it (it still does after Task 1 — keep it), and add
  `supported_groups: vec!["X25519".into(), "P-256".into()],` and
  `skipped_curves: vec![],`.
- `rendered_profile_loads_back_through_custom_loader`: change
  `assert_eq!(profile.spec.tls.cipher_suites, vec!["TLS_AES_128_GCM_SHA256"]);`
  — still valid. Add `assert_eq!(profile.spec.tls.supported_groups, vec!["X25519", "P-256"]);`.
- `http1_fallback_block_is_still_loadable`: unchanged logic; still valid.
- `write_profile_creates_dir_and_file`: unchanged.

- [ ] **Step 12: Update `capture_e2e.rs` assertions**

In `crates/roxy-capture/tests/capture_e2e.rs`, replace the line
`assert!(!profile.spec.tls.extensions.is_empty(), ...)` with:

```rust
    assert!(
        !profile.spec.tls.supported_groups.is_empty(),
        "captured supported_groups should not be empty"
    );
```

Leave the `settings_order` / `header_order` assertions as-is (those fields still exist).

- [ ] **Step 13: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: PASS — all crates compile, all tests green. If `cargo clippy --workspace --all-targets` reports `unwrap_used`/`expect_used` in new non-test code, fix inline.

- [ ] **Step 14: Commit**

```bash
git add crates/roxy-impersonate/src/custom.rs crates/roxy-impersonate/src/client.rs \
  crates/roxy-proxy/tests/impersonate.rs crates/roxy-proxy/tests/fingerprint_smoke.rs \
  crates/roxy-capture/src/client_hello.rs crates/roxy-capture/src/profile.rs \
  crates/roxy-capture/tests/capture_e2e.rs
git commit -m "refactor(roxy-impersonate,roxy-capture): reshape custom profile schema to mirror wreq builders"
```

---

## Task 2: Capture GREASE presence

**Files:**
- Modify: `crates/roxy-capture/src/client_hello.rs`
- Modify: `crates/roxy-capture/src/profile.rs`

- [ ] **Step 1: Write the failing test**

Add to `client_hello.rs`'s `#[cfg(test)] mod tests` — but `parse` needs real
ClientHello bytes. Instead test the field plumbing via `profile.rs`. Add to
`profile.rs`'s test module:

```rust
    #[test]
    fn grease_true_emits_grease_field() {
        let name = ProfileName::parse("captured-grease").unwrap();
        let mut tls = sample_tls();
        tls.grease = true;
        let toml = render(&name, &tls, Some(&sample_http2()), Some(b"h2"));
        assert!(toml.contains("grease = true"), "toml:\n{toml}");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p roxy-capture grease_true_emits_grease_field`
Expected: FAIL — `CapturedTls` has no field `grease`.

- [ ] **Step 3: Add the `grease` field and detection**

In `client_hello.rs`, add `pub grease: bool,` to `CapturedTls`. In `parse`, add
`let mut grease = false;`. In the cipher loop, when `is_grease(id)` is hit, also
set `grease = true;`. In the extension loop, change the GREASE-extension skip to:

```rust
            if matches!(ext, TlsExtension::Grease(..)) {
                grease = true;
                continue;
            }
```

Also set `grease = true` inside the existing `is_grease` checks in the
`SupportedVersions`, `SignatureAlgorithms`, and `EllipticCurves` arms. Add
`grease` to the `CapturedTls { .. }` constructor.

In `profile.rs::render`, after the `out.push_str("[tls]\n")` core-identity block
and before the `out.push('\n')`, add:

```rust
    if tls.grease {
        out.push_str("grease = true\n");
    }
```

In `profile.rs` tests, add `grease: false,` to `sample_tls()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p roxy-capture grease_true_emits_grease_field`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/roxy-capture/src/client_hello.rs crates/roxy-capture/src/profile.rs
git commit -m "feat(roxy-capture): detect and emit GREASE presence"
```

---

## Task 3: Capture feature toggles from extension presence

Detects `enable_ocsp_stapling`, `enable_signed_cert_timestamps`,
`enable_ech_grease`, `session_ticket`, `renegotiation`, `record_size_limit`,
and `pre_shared_key_seen` from which extensions appear in the ClientHello.

**Files:**
- Modify: `crates/roxy-capture/src/client_hello.rs`
- Modify: `crates/roxy-capture/src/profile.rs`

- [ ] **Step 1: Write the failing test**

Add to `profile.rs` test module:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p roxy-capture feature_toggles_emit_when_set`
Expected: FAIL — `CapturedTls` has no such fields.

- [ ] **Step 3: Add fields, detection, and emission**

In `client_hello.rs`, add to `CapturedTls`:

```rust
    pub enable_ocsp_stapling: bool,
    pub enable_signed_cert_timestamps: bool,
    pub enable_ech_grease: bool,
    pub session_ticket: bool,
    pub renegotiation: bool,
    pub record_size_limit: Option<u16>,
    pub pre_shared_key_seen: bool,
```

In `parse`, add accumulators initialised to `false`/`None`. In the `match ext`
block, add arms (these tls-parser variants exist: `StatusRequest`,
`SignedCertificateTimestamp`, `SessionTicket`, `RenegotiationInfo`,
`PreSharedKey`, `RecordSizeLimit`):

```rust
                TlsExtension::StatusRequest(_) => enable_ocsp_stapling = true,
                TlsExtension::SignedCertificateTimestamp(_) => {
                    enable_signed_cert_timestamps = true
                }
                TlsExtension::SessionTicket(_) => session_ticket = true,
                TlsExtension::RenegotiationInfo(_) => renegotiation = true,
                TlsExtension::PreSharedKey(_) => pre_shared_key_seen = true,
                TlsExtension::RecordSizeLimit(v) => record_size_limit = Some(*v),
```

ECH (type `65037`) has no typed tls-parser variant — detect it by type number.
Right after `let ty: u16 = TlsExtensionType::from(ext).0;`, add:

```rust
            if ty == 65037 {
                enable_ech_grease = true;
            }
```

Add all seven fields to the `CapturedTls { .. }` constructor.

In `profile.rs::render`, after the `grease` line, add:

```rust
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
```

In `profile.rs` tests, add the seven new fields (all `false`/`None`) to `sample_tls()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p roxy-capture feature_toggles_emit_when_set`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/roxy-capture/src/client_hello.rs crates/roxy-capture/src/profile.rs
git commit -m "feat(roxy-capture): detect TLS feature toggles from extension presence"
```

---

## Task 4: Capture ALPS and certificate compression

ALPS (`application_settings`) and `compress_certificate` are `TlsExtension::Unknown`
in tls-parser — parsed from raw extension bytes by type number.

**Files:**
- Modify: `crates/roxy-capture/src/client_hello.rs`
- Modify: `crates/roxy-capture/src/profile.rs`

- [ ] **Step 1: Write the failing test**

Add to `client_hello.rs` test module (these helpers test the byte parsers
directly, no full ClientHello needed):

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p roxy-capture parses_alps_protocol_list parses_cert_compression_algorithms`
Expected: FAIL — `parse_alpn_list` / `parse_cert_compression` not defined.

- [ ] **Step 3: Add fields, byte parsers, detection, and emission**

In `client_hello.rs`, add to `CapturedTls`:

```rust
    pub alps_protocols: Vec<String>,
    pub alps_use_new_codepoint: bool,
    pub cert_compression: Vec<String>,
```

Add the two byte-parser helpers:

```rust
/// Parse an ALPN-style protocol list: 2-byte list length, then a sequence of
/// (1-byte length, protocol bytes). Used for both ALPN and ALPS extension data.
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

/// Parse `compress_certificate` data: 1-byte count of following bytes, then
/// 2-byte algorithm ids. `1 → zlib`, `2 → brotli`, `3 → zstd`.
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
```

In `parse`, add accumulators `let mut alps_protocols = Vec::new();`,
`let mut alps_use_new_codepoint = false;`, `let mut cert_compression = Vec::new();`.
After the existing `let ty: u16 = ...` line, add:

```rust
            match ty {
                17513 => alps_protocols = parse_alpn_list(unknown_data(ext)),
                17613 => {
                    alps_protocols = parse_alpn_list(unknown_data(ext));
                    alps_use_new_codepoint = true;
                }
                27 => cert_compression = parse_cert_compression(unknown_data(ext)),
                _ => {}
            }
```

Add the `unknown_data` helper (returns the raw bytes for `Unknown`, empty otherwise):

```rust
/// Raw extension payload for a `TlsExtension::Unknown`; empty slice for typed
/// variants (which we never call this on).
fn unknown_data(ext: &TlsExtension) -> &[u8] {
    match ext {
        TlsExtension::Unknown(_, data) => data,
        _ => &[],
    }
}
```

Add the three new fields to the `CapturedTls { .. }` constructor.

In `profile.rs::render`, after the `record_size_limit` block, add:

```rust
    if !tls.alps_protocols.is_empty() {
        out.push_str(&format!(
            "alps_protocols = {}\n",
            string_array(&tls.alps_protocols)
        ));
        out.push_str(&format!(
            "alps_use_new_codepoint = {}\n",
            tls.alps_use_new_codepoint
        ));
    }
    if !tls.cert_compression.is_empty() {
        out.push_str(&format!(
            "cert_compression = {}\n",
            string_array(&tls.cert_compression)
        ));
    }
```

In `profile.rs` tests, add `alps_protocols: vec![]`, `alps_use_new_codepoint: false`,
`cert_compression: vec![]` to `sample_tls()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p roxy-capture parses_alps_protocol_list parses_cert_compression_algorithms`
Expected: PASS

- [ ] **Step 5: Run the crate test suite**

Run: `cargo test -p roxy-capture`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/roxy-capture/src/client_hello.rs crates/roxy-capture/src/profile.rs
git commit -m "feat(roxy-capture): detect ALPS and certificate-compression extensions"
```

---

## Task 5: Best-guess trio + extension_permutation fallback

For GREASE-positive clients, emit best-guess `permute_extensions`,
`aes_hw_override`, and `pre_shared_key` with `# guessed:` comments. For
non-GREASE clients, emit the observed extension order as `extension_permutation`.

**Files:**
- Modify: `crates/roxy-capture/src/profile.rs`

- [ ] **Step 1: Write the failing tests**

Add to `profile.rs` test module:

```rust
    #[test]
    fn grease_client_gets_best_guess_trio() {
        let name = ProfileName::parse("captured-guess").unwrap();
        let mut tls = sample_tls();
        tls.grease = true;
        tls.pre_shared_key_seen = false;
        let toml = render(&name, &tls, Some(&sample_http2()), Some(b"h2"));
        assert!(toml.contains("permute_extensions = true   # guessed"), "toml:\n{toml}");
        assert!(toml.contains("aes_hw_override = true   # guessed"), "toml:\n{toml}");
        assert!(toml.contains("pre_shared_key = true   # guessed"), "toml:\n{toml}");
        assert!(!toml.contains("extension_permutation"), "toml:\n{toml}");
    }

    #[test]
    fn non_grease_client_gets_extension_permutation() {
        let name = ProfileName::parse("captured-fixed").unwrap();
        let mut tls = sample_tls();
        tls.grease = false;
        tls.extensions = vec!["server_name".into(), "supported_groups".into()];
        let toml = render(&name, &tls, Some(&sample_http2()), Some(b"h2"));
        assert!(
            toml.contains(r#"extension_permutation = ["server_name", "supported_groups"]"#),
            "toml:\n{toml}"
        );
        assert!(!toml.contains("# guessed"), "toml:\n{toml}");
    }

    #[test]
    fn psk_seen_emits_plain_pre_shared_key() {
        let name = ProfileName::parse("captured-psk").unwrap();
        let mut tls = sample_tls();
        tls.grease = true;
        tls.pre_shared_key_seen = true;
        let toml = render(&name, &tls, Some(&sample_http2()), Some(b"h2"));
        assert!(toml.contains("pre_shared_key = true\n"), "toml:\n{toml}");
        assert!(!toml.contains("pre_shared_key = true   # guessed"), "toml:\n{toml}");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p roxy-capture -- grease_client_gets_best_guess_trio non_grease_client_gets_extension_permutation psk_seen_emits_plain_pre_shared_key`
Expected: FAIL — emitter does not produce these lines.

- [ ] **Step 3: Add the best-guess / fallback emission block**

In `profile.rs::render`, after the `cert_compression` block and before
`out.push('\n')`, add:

```rust
    if tls.grease {
        out.push_str("permute_extensions = true   # guessed: not observable from a single capture\n");
        out.push_str("aes_hw_override = true   # guessed: not observable on the wire\n");
        if tls.pre_shared_key_seen {
            out.push_str("pre_shared_key = true\n");
        } else {
            out.push_str(
                "pre_shared_key = true   # guessed: PSK only appears on session resumption\n",
            );
        }
    } else {
        if tls.pre_shared_key_seen {
            out.push_str("pre_shared_key = true\n");
        }
        if !tls.extensions.is_empty() {
            out.push_str(&format!(
                "extension_permutation = {}\n",
                string_array(&tls.extensions)
            ));
        }
    }
```

(`CapturedTls.extensions` is the observed ordered list of recognised extension
names, retained from before Task 1.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p roxy-capture -- grease_client_gets_best_guess_trio non_grease_client_gets_extension_permutation psk_seen_emits_plain_pre_shared_key`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/roxy-capture/src/profile.rs
git commit -m "feat(roxy-capture): best-guess undetectable knobs, extension_permutation fallback"
```

---

## Task 6: Make HTTP/2 settings optional + capture WINDOW_UPDATE

Reshape `CapturedHttp2` so settings values are `Option` (capture emits only what
the client actually sent — kills the spurious `MAX_FRAME_SIZE`), and capture the
connection-level `WINDOW_UPDATE` increment plus SETTINGS ids `0x8`/`0x9`.

**Files:**
- Modify: `crates/roxy-capture/src/h2.rs`
- Modify: `crates/roxy-capture/src/profile.rs`

- [ ] **Step 1: Write the failing test**

Replace the body of the existing `parses_settings_and_pseudo_header_order` test
in `h2.rs` with assertions against the new `Option` shape, and add a
WINDOW_UPDATE test:

```rust
    #[test]
    fn parses_settings_and_pseudo_header_order() {
        let mut buf = Vec::new();
        buf.extend_from_slice(PREFACE);
        buf.extend_from_slice(&frame(
            FRAME_SETTINGS,
            0,
            &settings_body(&[(0x1, 65536), (0x2, 0), (0x4, 6291456), (0x6, 262144)]),
        ));
        buf.extend_from_slice(&frame(
            FRAME_HEADERS,
            0x4,
            &hpack_block(&[
                (":method", "GET"),
                (":authority", "example.com"),
                (":scheme", "https"),
                (":path", "/"),
            ]),
        ));
        let h2 = parse_http2(&buf).expect("should parse");
        assert_eq!(h2.header_table_size, Some(65536));
        assert_eq!(h2.enable_push, Some(false));
        assert_eq!(h2.initial_window_size, Some(6291456));
        assert_eq!(h2.max_header_list_size, Some(262144));
        assert_eq!(h2.max_frame_size, None); // not sent — must not be emitted
        assert_eq!(
            h2.settings_order,
            vec!["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_HEADER_LIST_SIZE"]
        );
        assert_eq!(h2.header_order, vec![":method", ":authority", ":scheme", ":path"]);
    }

    #[test]
    fn captures_connection_window_update() {
        let mut buf = Vec::new();
        buf.extend_from_slice(PREFACE);
        buf.extend_from_slice(&frame(FRAME_SETTINGS, 0, &settings_body(&[(0x2, 0)])));
        // WINDOW_UPDATE frame, stream 0, increment 15663105 (0x00EF0001).
        let mut wu = vec![0, 0, 4, 0x8, 0, 0, 0, 0, 0];
        wu.extend_from_slice(&15663105u32.to_be_bytes());
        buf.extend_from_slice(&wu);
        buf.extend_from_slice(&frame(FRAME_HEADERS, 0x4, &hpack_block(&[(":method", "GET")])));
        let h2 = parse_http2(&buf).expect("should parse");
        assert_eq!(h2.initial_connection_window_size, Some(15663105));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p roxy-capture --lib h2`
Expected: FAIL — `CapturedHttp2` fields are not `Option`; no `initial_connection_window_size`.

- [ ] **Step 3: Reshape `CapturedHttp2` and `parse_http2`**

In `h2.rs`, replace the `CapturedHttp2` struct with:

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedHttp2 {
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub enable_connect_protocol: Option<bool>,
    pub no_rfc7540_priorities: Option<bool>,
    pub settings_order: Vec<String>,
    pub header_order: Vec<String>,
}
```

Add `const FRAME_WINDOW_UPDATE: u8 = 0x8;` next to the other frame constants.

In `parse_http2`, replace the RFC-default `let mut` declarations with all-`None`
optionals and a `let mut initial_connection_window_size: Option<u32> = None;`,
then update the `FRAME_SETTINGS` arm's inner `match id` to assign `Some(...)`:

```rust
                    match id {
                        0x1 => header_table_size = Some(value),
                        0x2 => enable_push = Some(value != 0),
                        0x3 => max_concurrent_streams = Some(value),
                        0x4 => initial_window_size = Some(value),
                        0x5 => max_frame_size = Some(value),
                        0x6 => max_header_list_size = Some(value),
                        0x8 => enable_connect_protocol = Some(value != 0),
                        0x9 => no_rfc7540_priorities = Some(value != 0),
                        _ => {}
                    }
```

Add a new match arm for the WINDOW_UPDATE frame (connection-level = stream id 0):

```rust
            FRAME_WINDOW_UPDATE if initial_connection_window_size.is_none() => {
                let stream_id = u32::from_be_bytes([
                    cursor[5] & 0x7f,
                    cursor[6],
                    cursor[7],
                    cursor[8],
                ]);
                if stream_id == 0 && body.len() >= 4 {
                    let inc = u32::from_be_bytes([body[0], body[1], body[2], body[3]])
                        & 0x7fff_ffff;
                    initial_connection_window_size = Some(inc);
                }
            }
```

Update the loop's early-exit condition and the `CapturedHttp2 { .. }`
constructor to include all the new fields. The early-exit stays
`if got_settings && header_order.is_some() { break; }` — the WINDOW_UPDATE
arrives between SETTINGS and HEADERS so it is always seen first.

- [ ] **Step 4: Update `profile.rs::render` HTTP/2 block**

In `profile.rs::render`, replace the `Some(h)` arm of the `match http2` block with:

```rust
        Some(h) => {
            if let Some(v) = h.header_table_size {
                out.push_str(&format!("header_table_size = {v}\n"));
            }
            if let Some(v) = h.enable_push {
                out.push_str(&format!("enable_push = {v}\n"));
            }
            if let Some(v) = h.max_concurrent_streams {
                out.push_str(&format!("max_concurrent_streams = {v}\n"));
            }
            if let Some(v) = h.initial_window_size {
                out.push_str(&format!("initial_window_size = {v}\n"));
            }
            if let Some(v) = h.initial_connection_window_size {
                out.push_str(&format!("initial_connection_window_size = {v}\n"));
            }
            if let Some(v) = h.max_frame_size {
                out.push_str(&format!("max_frame_size = {v}\n"));
            }
            if let Some(v) = h.max_header_list_size {
                out.push_str(&format!("max_header_list_size = {v}\n"));
            }
            if let Some(v) = h.enable_connect_protocol {
                out.push_str(&format!("enable_connect_protocol = {v}\n"));
            }
            if let Some(v) = h.no_rfc7540_priorities {
                out.push_str(&format!("no_rfc7540_priorities = {v}\n"));
            }
            out.push_str(&format!("settings_order = {}\n", string_array(&h.settings_order)));
            out.push_str(&format!("header_order = {}\n", string_array(&h.header_order)));
        }
```

Update `profile.rs`'s `sample_http2()` helper to the new `Option` shape:

```rust
    fn sample_http2() -> CapturedHttp2 {
        CapturedHttp2 {
            header_table_size: Some(65536),
            enable_push: Some(false),
            max_concurrent_streams: None,
            initial_window_size: Some(6291456),
            initial_connection_window_size: None,
            max_frame_size: None,
            max_header_list_size: Some(262144),
            enable_connect_protocol: None,
            no_rfc7540_priorities: None,
            settings_order: vec!["HEADER_TABLE_SIZE".into(), "ENABLE_PUSH".into()],
            header_order: vec![":method".into(), ":authority".into()],
        }
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p roxy-capture`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/roxy-capture/src/h2.rs crates/roxy-capture/src/profile.rs
git commit -m "feat(roxy-capture): optional HTTP/2 settings + WINDOW_UPDATE capture"
```

---

## Task 7: Capture HEADERS-frame stream dependency

Extract the priority bytes from the first HEADERS frame (when the `PRIORITY`
flag is set) instead of skipping them, and emit them as
`[http2.headers_stream_dependency]`.

**Files:**
- Modify: `crates/roxy-capture/src/h2.rs`
- Modify: `crates/roxy-capture/src/profile.rs`

- [ ] **Step 1: Write the failing test**

Add to `h2.rs` test module:

```rust
    #[test]
    fn captures_headers_stream_dependency() {
        let block = hpack_block(&[(":method", "GET")]);
        let mut body = Vec::new();
        // PRIORITY prefix: 4-byte (exclusive bit + dependency), 1-byte weight.
        body.extend_from_slice(&[0x80, 0, 0, 0, 219]); // exclusive=1, dep=0, weight=219
        body.extend_from_slice(&block);
        let mut buf = Vec::new();
        buf.extend_from_slice(PREFACE);
        buf.extend_from_slice(&frame(FRAME_SETTINGS, 0, &settings_body(&[(0x2, 0)])));
        buf.extend_from_slice(&frame(FRAME_HEADERS, 0x4 | 0x20, &body)); // END_HEADERS | PRIORITY
        let h2 = parse_http2(&buf).expect("should parse");
        let dep = h2.headers_stream_dependency.expect("priority should be captured");
        assert_eq!(dep.stream_id, 0);
        assert_eq!(dep.weight, 219);
        assert!(dep.exclusive);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p roxy-capture --lib captures_headers_stream_dependency`
Expected: FAIL — no `headers_stream_dependency` field / `CapturedStreamDependency` type.

- [ ] **Step 3: Add the type, field, and extraction**

In `h2.rs`, add the struct and a `CapturedHttp2` field:

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedStreamDependency {
    pub stream_id: u32,
    pub weight: u8,
    pub exclusive: bool,
}
```

Add `pub headers_stream_dependency: Option<CapturedStreamDependency>,` to
`CapturedHttp2`.

Change `decode_pseudo_order` to also return the priority info. Replace its
signature and the priority-handling block:

```rust
fn decode_pseudo_order(
    body: &[u8],
    flags: u8,
) -> (Vec<String>, Option<CapturedStreamDependency>) {
    let mut block = body;
    let mut pad_len = 0usize;
    if flags & FLAG_PADDED != 0 {
        let Some((first, rest)) = block.split_first() else {
            return (Vec::new(), None);
        };
        pad_len = *first as usize;
        block = rest;
    }
    let mut stream_dependency = None;
    if flags & FLAG_PRIORITY != 0 {
        if block.len() < 5 {
            return (Vec::new(), None);
        }
        let raw = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        stream_dependency = Some(CapturedStreamDependency {
            stream_id: raw & 0x7fff_ffff,
            weight: block[4],
            exclusive: raw & 0x8000_0000 != 0,
        });
        block = &block[5..];
    }
    if pad_len > block.len() {
        return (Vec::new(), stream_dependency);
    }
    block = &block[..block.len() - pad_len];

    let mut decoder = Decoder::default();
    let mut input = block.to_vec();
    let mut decoded: Vec<(Vec<u8>, Vec<u8>, u8)> = Vec::new();
    let _ = decoder.decode(&mut input, &mut decoded);

    let order = decoded
        .iter()
        .filter_map(|(name, _, _)| {
            let name = std::str::from_utf8(name).ok()?;
            name.starts_with(':').then(|| name.to_string())
        })
        .collect();
    (order, stream_dependency)
}
```

In `parse_http2`, add `let mut headers_stream_dependency = None;`, and change the
`FRAME_HEADERS` arm to:

```rust
            FRAME_HEADERS if header_order.is_none() => {
                let (order, dep) = decode_pseudo_order(body, flags);
                header_order = Some(order);
                headers_stream_dependency = dep;
            }
```

Add `headers_stream_dependency` to the `CapturedHttp2 { .. }` constructor.

Update the existing `handles_padded_and_priority_headers_flags` test: it calls
`decode_pseudo_order` and now gets a tuple — change to
`let (order, _) = decode_pseudo_order(&body, FLAG_PADDED | FLAG_PRIORITY);`.

- [ ] **Step 4: Emit it in `profile.rs::render`**

In `profile.rs::render`, inside the `Some(h)` arm, after the `header_order` line:

```rust
            if let Some(dep) = &h.headers_stream_dependency {
                out.push_str("\n[http2.headers_stream_dependency]\n");
                out.push_str(&format!("stream_id = {}\n", dep.stream_id));
                out.push_str(&format!("weight = {}\n", dep.weight));
                out.push_str(&format!("exclusive = {}\n", dep.exclusive));
            }
```

Add `headers_stream_dependency: None,` to `profile.rs`'s `sample_http2()`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p roxy-capture`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/roxy-capture/src/h2.rs crates/roxy-capture/src/profile.rs
git commit -m "feat(roxy-capture): capture HEADERS-frame stream dependency"
```

---

## Task 8: Round-trip integration test for the enriched capture

Extend `capture_e2e.rs` to assert the new fields survive capture → render →
`CustomProfile::load` for a real Chrome emulation.

**Files:**
- Modify: `crates/roxy-capture/tests/capture_e2e.rs`

- [ ] **Step 1: Add assertions to the existing e2e test**

In `captures_real_browser_fingerprint_into_loadable_profile`, after the existing
`profile` assertions, add:

```rust
    // wreq's Chrome 137 emulation GREASEs, sends modern curves, ALPS, and a
    // permuted extension order — the enriched capture must record those.
    assert!(profile.spec.tls.grease == Some(true), "GREASE should be detected");
    assert!(
        !profile.spec.tls.supported_groups.is_empty(),
        "supported_groups should be captured"
    );
    assert!(
        profile.spec.tls.permute_extensions == Some(true),
        "GREASE client should get permute_extensions best-guess"
    );
    assert!(
        profile.spec.tls.extension_permutation.is_empty(),
        "permuting client must not also pin extension_permutation"
    );
```

- [ ] **Step 2: Run the e2e test**

Run: `cargo test -p roxy-capture --test capture_e2e`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add crates/roxy-capture/tests/capture_e2e.rs
git commit -m "test(roxy-capture): assert enriched fields survive capture round-trip"
```

---

## Task 9: Fingerprint-fidelity smoke test

A network-gated (`#[ignore]`) test that replays a known-good `chrome-148`
profile through roxy to `https://tls.peet.ws/api/all` and asserts `ja4_r` and
`peetprint` match real Chrome 148, modulo the documented `0xca34` extension
delta. This is the acceptance gate for the whole plan: it exercises the
schema + `build_emulation` + wreq path end to end.

The profile-under-test is an inline `const` derived from real Chrome 148
ClientHello + HTTP/2 data (the reference capture in the design doc). It is a
golden fixture, not a placeholder — if the `--ignored` run does not match, that
is a real bug in Tasks 1–8.

**Files:**
- Create: `crates/roxy-proxy/tests/fingerprint_fidelity.rs`

- [ ] **Step 1: Create the test file**

Create `crates/roxy-proxy/tests/fingerprint_fidelity.rs` with this exact content
(harness mirrors `fingerprint_smoke.rs`):

```rust
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

//! Ring 3 fidelity gate: a known-good chrome-148 profile, replayed through
//! roxy, must reproduce real Chrome 148's JA4_r and peetprint — except for the
//! one documented hard limit, TLS extension 51764 (0xca34), which wreq exposes
//! no knob for.
//!
//! `#[ignore]` because it requires public network access. Run with:
//!   cargo test -p roxy-proxy --test fingerprint_fidelity -- --ignored --nocapture

mod common;

use common::{Fixture, FixtureBuilder};
use roxy_proxy_lib::handler::FINGERPRINT_HEADER;
use serde_json::Value;

/// JA4_r of real Chrome 148 against tls.peet.ws, recorded 2026-05-14.
const REAL_CHROME_148_JA4R: &str = "t13d1518h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,ca34,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601";

/// peetprint of real Chrome 148 against tls.peet.ws, recorded 2026-05-14.
const REAL_CHROME_148_PEETPRINT: &str = "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-41-43-45-5-51-51764-65037-65281-GREASE-GREASE";

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
initial_connection_window_size = 15663105
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
    let got_ja4r = tls.get("ja4_r").and_then(|v| v.as_str()).expect("tls.ja4_r");
    let got_peet = tls
        .get("peetprint")
        .and_then(|v| v.as_str())
        .expect("tls.peetprint");

    // JA4_r = <ja4_a>_<ciphers>_<extensions>_<sigalgs>. Compare the cipher and
    // sigalg sections verbatim; compare the extension section after removing
    // 0xca34 (51764) from the real value — wreq cannot emit it (hard limit).
    let real: Vec<&str> = REAL_CHROME_148_JA4R.split('_').collect();
    let got: Vec<&str> = got_ja4r.split('_').collect();
    assert_eq!(got.len(), 4, "unexpected JA4_r shape: {got_ja4r}");
    assert_eq!(got[1], real[1], "JA4_r cipher section mismatch");
    assert_eq!(got[3], real[3], "JA4_r sigalg section mismatch");
    assert_eq!(
        got[2],
        real[2].replace("ca34,", ""),
        "JA4_r extension section mismatch (0xca34 excluded)"
    );

    // peetprint: the final pipe-section is the sorted extension list; drop
    // 51764 from the real value before comparing.
    assert_eq!(
        got_peet,
        REAL_CHROME_148_PEETPRINT.replace("-51764", ""),
        "peetprint mismatch (51764 excluded)"
    );

    drop(dir);
}
```

- [ ] **Step 2: Verify it compiles and is correctly ignored**

Run: `cargo test -p roxy-proxy --test fingerprint_fidelity`
Expected: PASS with `0 passed; 1 ignored` (the test is `#[ignore]`).

- [ ] **Step 3: Run the fidelity gate against the network**

Run: `cargo test -p roxy-proxy --test fingerprint_fidelity -- --ignored --nocapture`
Expected: PASS — JA4_r cipher/extension/sigalg sections and peetprint match real
Chrome 148 with `0xca34` excluded. If it fails, the `--nocapture` output shows
the exact diff; investigate which schema field or `build_emulation` knob is
still wrong (this gate exists to catch exactly that).

- [ ] **Step 4: Commit**

```bash
git add crates/roxy-proxy/tests/fingerprint_fidelity.rs
git commit -m "test(roxy-proxy): JA4_r + peetprint fidelity gate for captured profiles"
```

---

## Final Verification

- [ ] **Run the whole suite + clippy**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets`
Expected: all tests pass (ignored network tests skipped), clippy clean.

- [ ] **Manual end-to-end check**

1. `cargo run -p roxy-proxy -- ca install`
2. Run roxy with `[capture] enabled = true` and `default_profile = "chrome-148"`.
3. In a real Chrome 148, visit `https://localhost:8091/?name=chrome-148` —
   confirm the emitted TOML now contains `supported_groups`, `grease = true`,
   `alps_protocols`, the feature toggles, and `[http2.headers_stream_dependency]`.
4. With Chrome configured to use roxy as its proxy, visit
   `https://tls.peet.ws/api/all` — confirm `ja4_r` and `peetprint` match real
   Chrome 148 except for extension `51764` (`0xca34`).
