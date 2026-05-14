# High-Fidelity Custom Profiles — Design

**Date:** 2026-05-14
**Status:** Approved (brainstorming → design)
**Crates touched:** `roxy-impersonate`, `roxy-capture`

## Context

Roxy emulates browser TLS/HTTP-2 fingerprints on its upstream path. For
browsers wreq ships no builtin for (e.g. Chrome 148), the operator captures a
custom profile TOML via `roxy-capture` and roxy replays it through wreq.

Testing a captured `chrome-148` profile against `https://tls.peet.ws/api/all`
showed the emulated fingerprint is far from real Chrome 148:

- **JA4** `t13d1511h2_8daaf6152771_9ced094328c9` vs real `t13d1518h2_8daaf6152771_0c9ac9b5c72c`
- **JA4_r** — cipher list and signature algorithms are **byte-identical** to
  real Chrome, but roxy emits **9 extensions where Chrome sends 16** (sorted).
- **peetprint** — no GREASE anywhere; `supported_groups` is the BoringSSL
  default `29-23-24` instead of `GREASE-4588-29-23-24` (missing X25519MLKEM768).
- **HTTP/2** — roxy sends a spurious `MAX_FRAME_SIZE` setting Chrome never
  sends, and the `WINDOW_UPDATE` increment is a default, not Chrome's value.

### Root cause

Comparison against wreq-util's *builtin* Chrome emulation (`ChromeTlsConfig →
TlsOptions`) — the fidelity ceiling — shows the entire gap is **unset wreq
knobs**, not buggy application. `roxy-impersonate`'s `custom.rs` wires roughly 7
of the ~15 fingerprint-relevant `TlsOptionsBuilder` knobs; everything else falls
to BoringSSL defaults.

The miss maps 1:1:

| Missing in roxy's emulation | Unset wreq knob |
| --- | --- |
| extensions `5`, `18`, `27`, `41`, `17613`, `65037` | `enable_ocsp_stapling`, `enable_signed_cert_timestamps`, `certificate_compression_algorithms`, `pre_shared_key`, `alps_protocols`, `enable_ech_grease` |
| GREASE absent everywhere | `grease_enabled` |
| `supported_groups` = default `29-23-24` | `curves_list` (+ `grease_enabled`) |
| spurious HTTP/2 `MAX_FRAME_SIZE` | `Http2Spec` makes `max_frame_size` a required field |
| HTTP/2 `WINDOW_UPDATE` increment wrong | no `initial_connection_window_size` field |
| extension `51764` (`0xca34`) | no wreq knob exists — see Hard Limits |

A second, structural problem: roxy's `TlsSpec` has an `extensions = [...]` list.
Chrome **permutes its extension order every connection** — that is *why* JA4_r
and peetprint both sort extensions. There is no canonical extension order to
capture. The extension *set* is an emergent property of the feature toggles;
listing extensions is the wrong abstraction.

### Goal

Make a captured profile reproduce real Chrome 148's **JA4_r and peetprint**
(exact cipher/group/sigalg/version ordering and the full extension set; ignoring
per-connection-random payloads, which both fingerprints already exclude).

### Decisions locked during brainstorming

1. **Target bar:** JA4_r + peetprint match (strict — ordering and sets, not
   hashes-only, not byte-identical).
2. **Schema philosophy:** mirror wreq's *fingerprint-relevant* builder surface
   1:1. Each knob becomes an optional TOML field. Connection-behavior knobs
   (`keep_alive_interval`, `max_send_buf_size`, `adaptive_window`, …) are
   excluded — they never appear on the wire.
3. **Undetectable knobs:** capture writes a best-guess value inline with a
   `# guessed: …` comment (vs. omitting, or a browser-family recognition table).

## Section 1 — Schema reshape (`roxy-impersonate`)

`TlsSpec` and `Http2Spec` are reshaped to mirror wreq's fingerprint-relevant
builder surface. **Every field becomes optional.** `build_emulation` calls a
builder method only when the field is present; anything omitted falls through to
wreq's default. Capture emits only what it detects.

A captured `chrome-148.toml` under the new schema:

```toml
name = "chrome-148"

[tls]
# core identity — ordered, GREASE excluded (wreq re-adds it)
cipher_suites        = ["TLS_AES_128_GCM_SHA256", "...15 total..."]
signature_algorithms = ["ecdsa_secp256r1_sha256", "...8 total..."]
supported_groups     = ["X25519MLKEM768", "X25519", "P-256", "P-384"]   # NEW
supported_versions   = ["TLS1.3", "TLS1.2"]
alpn                 = ["h2", "http/1.1"]

# feature toggles — omit = wreq default                                   # ALL NEW
grease                        = true
enable_ocsp_stapling          = true
enable_signed_cert_timestamps = true
enable_ech_grease             = true
session_ticket                = true
renegotiation                 = true
pre_shared_key     = true   # guessed: PSK only appears on session resumption
permute_extensions = true   # guessed: not observable from a single capture
aes_hw_override    = true   # guessed: not observable on the wire

# typed lists — omit = not sent                                           # NEW
alps_protocols         = ["h2"]
alps_use_new_codepoint = true
cert_compression       = ["brotli"]
# also available, omitted here: record_size_limit, key_shares_limit,
# delegated_credentials, extension_permutation

[http2]
header_table_size              = 65536
enable_push                    = false
initial_window_size            = 6291456
initial_connection_window_size = 15663105   # NEW — the WINDOW_UPDATE increment
max_header_list_size           = 262144
# max_frame_size omitted — real Chrome doesn't send it
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_HEADER_LIST_SIZE"]
header_order   = [":method", ":authority", ":scheme", ":path"]

[http2.headers_stream_dependency]   # NEW — HEADERS-frame priority
stream_id = 0
weight    = 256
exclusive = true
```

### `TlsSpec` fields

Kept (made optional where they were required): `cipher_suites`,
`signature_algorithms`, `supported_versions`, `alpn`,
`preserve_tls13_cipher_list`.

New, each mapping to a `TlsOptionsBuilder` knob:
`supported_groups` (→ `curves_list`), `grease` (→ `grease_enabled`),
`enable_ocsp_stapling`, `enable_signed_cert_timestamps`, `enable_ech_grease`,
`session_ticket`, `renegotiation`, `pre_shared_key`, `permute_extensions`,
`aes_hw_override`, `alps_protocols`, `alps_use_new_codepoint`, `cert_compression`
(→ `certificate_compression_algorithms`), `record_size_limit`,
`key_shares_limit`, `delegated_credentials`, `extension_permutation`.

### `Http2Spec` fields

Kept (made optional): `header_table_size`, `enable_push`, `initial_window_size`,
`max_frame_size`, `max_header_list_size`, `settings_order`, `header_order`.

New: `initial_connection_window_size`, `max_concurrent_streams`,
`enable_connect_protocol`, `no_rfc7540_priorities`, `headers_stream_dependency`
(a sub-table: `stream_id`, `weight`, `exclusive`).

### Key decisions

1. **The `extensions` list is removed.** Replaced by two wreq knobs:
   `permute_extensions` (bool — what Chrome does) and `extension_permutation`
   (a fixed ordered list — for non-permuting clients such as Safari/okhttp).
   These are mutually exclusive in practice.
2. **All settings/toggles optional** — fixes the spurious `MAX_FRAME_SIZE`: if
   `max_frame_size` is absent, roxy never calls that builder method.
3. **`#[serde(deny_unknown_fields)]`** is added to the spec structs — old
   profiles carrying `extensions = [...]` fail loudly with a migration message
   instead of silently dropping the field.
4. **Field names stay human-friendly** where they already exist (`cipher_suites`,
   not wreq's `cipher_list`). New fields get descriptive names
   (`supported_groups`, `cert_compression`). "Mirror 1:1" applies to *knob
   coverage*, not literal field names.

### Migration

Breaking change to the TOML format. Pre-1.0; the only existing files are
operators' own captures. `deny_unknown_fields` turns an old `extensions = [...]`
file into a clear load-time error directing the operator to re-capture with the
new `roxy-capture` (or rename the field to `extension_permutation`).

## Section 2 — Application (`roxy-impersonate/src/custom.rs`)

`build_emulation` is rewritten as a mechanical "for each `Some` field, call the
matching builder method." This is the smallest part — `cipher_list`, `sigalgs`,
`alpn`, versions, and HTTP/2 header-order already apply correctly today; this
wires the ~14 new knobs.

1. **TLS knobs** — straight pass-through to `TlsOptionsBuilder`, each guarded by
   `if let Some(v)`: `grease_enabled`, `curves_list`, `enable_ocsp_stapling`,
   `enable_signed_cert_timestamps`, `enable_ech_grease`, `session_ticket`,
   `renegotiation`, `pre_shared_key`, `permute_extensions`, `aes_hw_override`,
   `alps_protocols` + `alps_use_new_codepoint`,
   `certificate_compression_algorithms`, `record_size_limit`,
   `key_shares_limit`, `delegated_credentials`.
2. **New string→typed translations**, joining the existing
   `extension_from_str` / `setting_from_str` family:
   - curve name → wreq curve identifier (`curves_list` takes a colon-joined
     string, like `cipher_list`; this is validation + join)
   - cert-compression name → `CertificateCompressionAlgorithm` (`"brotli"` →
     `BROTLI`)
   - ALPS protocol → `AlpsProtocol`
   - `headers_stream_dependency` table → `StreamDependency::new(stream_id,
     weight, exclusive)`
3. **HTTP/2 — only set what's present.** Each setting value is `Option`, so
   `MAX_FRAME_SIZE` is emitted only when the profile carries it. Add
   `initial_connection_window_size`, `headers_stream_dependency`,
   `enable_connect_protocol`, `no_rfc7540_priorities`, `max_concurrent_streams`.
4. **Validation changes.** Require `cipher_suites`, `signature_algorithms`,
   `supported_groups`, `alpn` non-empty (core TLS identity) and `settings_order`
   + `header_order` non-empty (core HTTP/2 identity). Drop the `extensions`
   check (field is gone). Warn when `settings_order` names a setting with no
   value, or a value is set but not in `settings_order`.
5. **`extension_permutation` vs `permute_extensions`** — if both are set,
   `permute_extensions` wins and a warning is logged.

This section is almost entirely additive; nothing that already works changes
behavior.

## Section 3 — Capture (`roxy-capture`)

The bulk of the new code. The capture pipeline gains detection for every schema
field observable on the wire and best-guesses the three that aren't.

### ClientHello parser (`client_hello.rs`)

`CapturedTls` grows to mirror the new `TlsSpec`. New extraction:

- **`supported_groups`** — parse the `supported_groups` extension's curve list,
  map number→name (`29→X25519`, `23→P-256`, `24→P-384`, `4588→X25519MLKEM768`,
  `25497→X25519Kyber768Draft00`, …), GREASE filtered. Highest-impact addition.
- **`grease`** — `true` if any GREASE value appears in
  ciphers/groups/versions/extensions.
- **feature toggles from extension presence** — `status_request` →
  `enable_ocsp_stapling`; `signed_certificate_timestamp` →
  `enable_signed_cert_timestamps`; ECH (`65037`) → `enable_ech_grease`;
  `session_ticket` ext → `session_ticket`; `renegotiation_info` / SCSV →
  `renegotiation`; `record_size_limit` ext → `record_size_limit = <value>`.
- **ALPS** — detect the `application_settings` extension; codepoint `17513` →
  `alps_use_new_codepoint = false`, `17613` → `true`; parse the protocol list.
- **`cert_compression`** — parse `compress_certificate` algorithms (`2→brotli`,
  `1→zlib`, `3→zstd`).
- **best-guess trio (decision 3)** — when `grease` is detected (modern
  Chromium-family signal): emit `permute_extensions = true`,
  `aes_hw_override = true`, and `pre_shared_key = true` *if the PSK extension
  was not seen* — each with an inline `# guessed: …` comment. For non-GREASE
  clients: omit the guesses and instead emit `extension_permutation` with the
  observed extension order (fixed-order clients such as Safari/okhttp).

### HTTP/2 parser (`h2.rs`)

`CapturedHttp2` grows:

- **`initial_connection_window_size`** — capture the connection-level
  `WINDOW_UPDATE` frame (stream 0) increment. The frame walker already exists;
  add frame type `0x8`.
- **`headers_stream_dependency`** — when the HEADERS frame's `PRIORITY` flag
  (`0x20`) is set, extract the 5 priority bytes (stream dependency + weight +
  exclusive) instead of skipping them. `decode_pseudo_order` already locates
  them.
- **settings** — values are now `Option`, so capture naturally emits only what
  the client actually sent (this also kills the spurious `MAX_FRAME_SIZE` at the
  source). Add SETTINGS ids `0x8` / `0x9` → `enable_connect_protocol` /
  `no_rfc7540_priorities`.

### TOML emitter (`profile.rs`)

Rewritten for the new schema: optional fields omitted when absent; `# guessed:`
comments on the best-guess trio; the existing GREASE / skipped-extension notes;
a new `# NOTE:` for any extension with no roxy/wreq knob (the `0xca34` case).

## Section 4 — Hard limits & verification

### Hard limits

Documented in this spec and noted in emitted TOML:

- **Extension `51764` (`0xca34`)** — present in real Chrome 148, but wreq's
  `TlsOptionsBuilder` exposes no knob for it. JA4_r and peetprint will differ
  from real Chrome by exactly this one extension. The emitter flags it in a
  `# NOTE:` comment. This is the one known unavoidable delta.
- **ECH (`65037`)** — `enable_ech_grease` emits an ECH-*GREASE* extension. The
  extension *type* `65037` is present (so JA4_r/peetprint, which key on type,
  match), but the payload is GREASE, not a real ECH config. Acceptable for the
  chosen bar.
- **Ephemeral bytes** — `client_random`, `session_id`, key-share payloads, PSK
  data — per-connection random. JA4_r and peetprint exclude or sort these out
  by design; stated here only for completeness.

**Expected outcome:** JA4_r and peetprint match real Chrome 148 **except for the
single `0xca34` extension** — i.e. `t13d1517…` vs real `t13d1518…` and a
one-entry difference in the sorted extension list. Cipher list, sigalgs, curves,
GREASE, all other extensions, and version order match exactly.

### Verification

1. **Unit tests** — parser fixtures exercising GREASE, curves (incl.
   X25519MLKEM768), ALPS codepoint detection, cert-compression, ECH, the
   `WINDOW_UPDATE` frame, and HEADERS-priority extraction; the
   render→`CustomProfile::load` round-trip extended to the full new schema.
2. **e2e test** (`roxy-capture/tests/capture_e2e.rs`) — extended to assert the
   new fields survive capture → render → load.
3. **Fidelity test** — a new `#[ignore]` network test (sibling to
   `roxy-proxy/tests/fingerprint_smoke.rs`): drive the captured `chrome-148`
   profile through roxy to `https://tls.peet.ws/api/all`, parse the JSON, and
   assert `ja4_r` and `peetprint` equal real Chrome 148 **modulo the documented
   `0xca34` delta**. This is the acceptance gate.
4. **Manual** — capture `chrome-148` via the capture server, run roxy with
   `default_profile = "chrome-148"`, hit tls.peet.ws, eyeball the diff.

## Effort shape & ordering

One coherent feature across two crates, with a strict dependency chain:

1. **Section 1 (Schema)** lands first — everything else consumes it.
2. **Section 2 (Application)** and **Section 3 (Capture)** can then proceed in
   parallel.
3. **Section 4 (fidelity test)** ties it off.

One spec, one implementation plan.
