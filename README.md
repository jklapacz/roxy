# roxy

Roxy is a caching proxy written in rust. The purpose of roxy is to provide a lightweight, and performant proxy that forwards requests to other upstreams (either proxies or direct) while allowing for content-addressible caching to occur.

# Features
- Configurable caching based on heuristics + configs to compute the cache key (based on request)
- Caching occurs at the content level, thus connection MITM is required
- Configurable upstream proxy support
- HTTP proxy interface
- Byte-accurate emulation of Chrome, Firefox, Safari, Edge, and OkHttp TLS + HTTP/2 fingerprints via [wreq](https://docs.rs/wreq) (anti-bot evasion territory; see "Fingerprint emulation" below)
- Support HTTP2 and HTTP1 protocols

# Fingerprint emulation

roxy can rewrite the TLS ClientHello and HTTP/2 SETTINGS on its **upstream** connections so origins see Chrome/Firefox/Safari/Edge bytes instead of the default rustls+hyper fingerprint. The client-facing side (where the application connects to roxy) is unchanged.

## Configuration

```toml
[impersonate]
# Optional. If set, every upstream request without an explicit override uses this profile.
default_profile = "chrome-137"

# Optional. Directory of *.toml custom profile specs.
# Defaults to "./profiles" (relative to roxy's working directory).
profiles_dir = "./profiles"

# Strip the X-Roxy-Fingerprint header before forwarding upstream. Default true.
strip_header = true
```

CLI override: `roxy serve --fingerprint chrome-137` (or `--fingerprint none` to force the unfingerprinted rustls path).

## Per-request override

Send `X-Roxy-Fingerprint: <name>` on a request through roxy to pick a profile for just that request. Special value `none` opts out of the configured default.

Unknown profile names return 502. Multiple or malformed `X-Roxy-Fingerprint` headers return 400.

## Builtin profiles

- `chrome-137`, `firefox-139`, `safari-18-3-1`, `edge-134`, `okhttp-5`

Backed by `wreq_util::Emulation` variants. Adding a new browser version is a one-line change in `crates/roxy-impersonate/src/profile.rs` once wreq ships the variant.

## Custom profiles

For browsers wreq doesn't yet ship presets for, drop a TOML file in `profiles_dir`. Schema example:

```toml
name = "chrome-148"

[tls]
alpn = ["h2", "http/1.1"]
cipher_suites = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
extensions = ["server_name", "supported_groups", "key_share", "supported_versions", "signature_algorithms"]
supported_versions = ["TLS1.3", "TLS1.2"]
signature_algorithms = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_frame_size = 16384
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE"]
header_order = [":method", ":authority", ":scheme", ":path", "user-agent", "accept"]
```

The full design + capture workflow is in `docs/superpowers/specs/2026-05-13-tls-fingerprint-emulation-design.md`.

## Build prerequisites

roxy now depends on BoringSSL via `wreq` + `boring2`. You'll need `cmake`, `perl`, and `clang` available on the builder. On macOS: `brew install cmake`. On Linux: `apt-get install cmake clang perl`.

# Upgrading

- **Cache key format changed**: the cache key now includes a profile-label component so different fingerprints don't share cache entries. Pre-existing `.cache` directories (typically `~/.local/share/roxy/cache`) will not be readable after upgrade — they're effectively invalidated. Clear the directory once after upgrading: `rm -rf ~/.local/share/roxy/cache`.
