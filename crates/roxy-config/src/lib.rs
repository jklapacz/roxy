#![cfg_attr(test, allow(clippy::unwrap_used))]

mod error;
pub use error::ConfigError;

mod proxy;
pub use proxy::{parse_proxy, ProxyAuth, ProxyEndpoint};

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub listen: SocketAddr,
    pub cache: CacheConfig,
    pub ca: CaConfig,
    pub log: LogConfig,
    pub impersonate: ImpersonateConfig,
    pub capture: CaptureConfig,
    pub upstream: UpstreamConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CacheConfig {
    /// When false, roxy never serves from or writes to the cache — it still
    /// MITMs and proxies every request. Useful for testing fingerprint/MITM
    /// behavior in isolation. Default true.
    pub enabled: bool,
    pub dir: PathBuf,
    pub default_ttl_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CaConfig {
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct LogConfig {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ImpersonateConfig {
    /// Optional. If set, every upstream request without an explicit override
    /// uses this profile. Absent => unfingerprinted (rustls path).
    pub default_profile: Option<String>,
    /// Directory of `*.toml` custom profile specs.
    ///
    /// Defaults to `./profiles`, **relative to the current working directory**
    /// of the running roxy process (NOT to the config file's directory).
    /// Override via TOML to use an absolute path or an XDG path like
    /// `~/.config/roxy/profiles`. Path expansion (`~`, env vars) is applied
    /// the same way as `cache.dir` and `ca.dir`.
    pub profiles_dir: PathBuf,
    /// Strip the X-Roxy-Fingerprint header before forwarding upstream.
    pub strip_header: bool,
    /// Seed the wreq trust store with the OS native CA bundle (same source
    /// the rustls path uses via `.with_native_roots()`). Default `false`,
    /// which leaves wreq on its bundled `webpki-roots`. Useful when roxy
    /// sits behind a TLS-MITM proxy whose CA is already installed
    /// system-wide.
    pub use_native_certs: bool,
    /// Optional extra CA PEM file appended to the wreq trust store. When set
    /// without [`Self::use_native_certs`], this PEM **replaces** wreq's
    /// default trust — appropriate when one private CA signs every origin
    /// roxy will see (e.g. a TLS-MITM proxy). Path expansion (`~`, env vars)
    /// is applied the same way as `cache.dir`.
    pub trust_pem: Option<PathBuf>,
}

impl Default for ImpersonateConfig {
    fn default() -> Self {
        Self {
            default_profile: None,
            profiles_dir: PathBuf::from("./profiles"),
            strip_header: true,
            use_native_certs: false,
            trust_pem: None,
        }
    }
}

/// TLS-fingerprint capture server. Opt-in; runs on its own port. A browser
/// configured to trust roxy's CA can visit it to have its fingerprint captured
/// into a custom profile written under `impersonate.profiles_dir`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CaptureConfig {
    /// When false, the capture server is not started.
    pub enabled: bool,
    /// Address the capture server listens on (separate from the proxy port).
    pub listen: SocketAddr,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8091),
        }
    }
}

/// Upstream proxy configuration. v1 supports a single HTTP CONNECT proxy;
/// absent => roxy dials origins directly. The `proxy` string is the serde
/// representation — call [`UpstreamConfig::endpoint`] for the parsed form.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(default)]
pub struct UpstreamConfig {
    /// Optional `http://[user:pass@]host:port` upstream proxy.
    pub proxy: Option<String>,
}

impl UpstreamConfig {
    /// Parse the configured `proxy` string into a typed endpoint. `Ok(None)`
    /// when no proxy is configured.
    pub fn endpoint(&self) -> Result<Option<ProxyEndpoint>, ConfigError> {
        self.proxy.as_deref().map(parse_proxy).transpose()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            cache: CacheConfig::default(),
            ca: CaConfig::default(),
            log: LogConfig::default(),
            impersonate: ImpersonateConfig::default(),
            capture: CaptureConfig::default(),
            upstream: UpstreamConfig::default(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: PathBuf::from("~/.local/share/roxy/cache"),
            default_ttl_seconds: 3600,
        }
    }
}

impl Default for CaConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("~/.config/roxy/ca"),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

use std::path::Path;

pub fn load_from_path(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Err(ConfigError::NotFound(path.to_path_buf()));
    }
    let bytes = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&bytes)?;
    cfg.with_expanded_paths()
}

pub fn default_config_path() -> PathBuf {
    if let Some(dir) = dirs::config_dir() {
        dir.join("roxy").join("config.toml")
    } else {
        PathBuf::from("./roxy.toml")
    }
}

impl Config {
    pub fn with_expanded_paths(mut self) -> Result<Self, ConfigError> {
        self.cache.dir = expand(&self.cache.dir)?;
        self.ca.dir = expand(&self.ca.dir)?;
        self.impersonate.profiles_dir = expand(&self.impersonate.profiles_dir)?;
        if let Some(p) = self.impersonate.trust_pem.as_ref() {
            self.impersonate.trust_pem = Some(expand(p)?);
        }
        // Validate the proxy URL at load time so misconfiguration fails fast
        // at startup rather than at the first request. The parsed value is
        // discarded here; callers re-parse via `UpstreamConfig::endpoint`.
        self.upstream.endpoint()?;
        Ok(self)
    }
}

fn expand(p: &Path) -> Result<PathBuf, ConfigError> {
    let s = p.to_string_lossy();
    let expanded = shellexpand::full(&s).map_err(|e| ConfigError::Expand(e.to_string()))?;
    Ok(PathBuf::from(expanded.into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_spec() {
        let c = Config::default();
        assert_eq!(c.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(c.cache.default_ttl_seconds, 3600);
        assert_eq!(c.log.level, "info");
    }

    use std::io::Write as _;

    #[test]
    fn loads_partial_toml_with_defaults() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"listen = "0.0.0.0:9090""#).unwrap();
        writeln!(f, r#"[cache]"#).unwrap();
        writeln!(f, r#"default_ttl_seconds = 60"#).unwrap();
        let c = load_from_path(f.path()).unwrap();
        assert_eq!(c.listen.to_string(), "0.0.0.0:9090");
        assert_eq!(c.cache.default_ttl_seconds, 60);
        // Untouched fields keep defaults.
        assert_eq!(c.log.level, "info");
    }

    #[test]
    fn expands_home_in_cache_dir() {
        let c = Config::default().with_expanded_paths().unwrap();
        let s = c.cache.dir.to_string_lossy().to_string();
        assert!(!s.starts_with("~"), "got: {}", s);
    }

    #[test]
    fn missing_file_returns_not_found() {
        let err = load_from_path(std::path::Path::new("/nonexistent/roxy.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::NotFound(_)));
    }

    #[test]
    fn impersonate_section_defaults() {
        let c = Config::default();
        assert_eq!(c.impersonate.default_profile, None);
        assert_eq!(c.impersonate.profiles_dir, PathBuf::from("./profiles"));
        assert!(c.impersonate.strip_header);
    }

    #[test]
    fn cache_enabled_defaults_true() {
        assert!(Config::default().cache.enabled);
    }

    #[test]
    fn cache_enabled_parses_false_from_toml() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"[cache]"#).unwrap();
        writeln!(f, r#"enabled = false"#).unwrap();
        let c = load_from_path(f.path()).unwrap();
        assert!(!c.cache.enabled);
    }

    #[test]
    fn capture_section_defaults() {
        let c = Config::default();
        assert!(!c.capture.enabled);
        assert_eq!(c.capture.listen.to_string(), "127.0.0.1:8091");
    }

    #[test]
    fn capture_section_parses_from_toml() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"[capture]"#).unwrap();
        writeln!(f, r#"enabled = true"#).unwrap();
        writeln!(f, r#"listen = "127.0.0.1:9191""#).unwrap();
        let c = load_from_path(f.path()).unwrap();
        assert!(c.capture.enabled);
        assert_eq!(c.capture.listen.to_string(), "127.0.0.1:9191");
    }

    #[test]
    fn impersonate_section_parses_from_toml() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"[impersonate]"#).unwrap();
        writeln!(f, r#"default_profile = "chrome-137""#).unwrap();
        writeln!(f, r#"strip_header = false"#).unwrap();
        let c = load_from_path(f.path()).unwrap();
        assert_eq!(c.impersonate.default_profile.as_deref(), Some("chrome-137"));
        assert!(!c.impersonate.strip_header);
        assert_eq!(c.impersonate.profiles_dir, PathBuf::from("./profiles"));
    }

    #[test]
    fn upstream_section_defaults_to_no_proxy() {
        let c = Config::default();
        assert_eq!(c.upstream.proxy, None);
        assert_eq!(c.upstream.endpoint().unwrap(), None);
    }

    #[test]
    fn upstream_proxy_parses_from_toml() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"[upstream]"#).unwrap();
        writeln!(f, r#"proxy = "http://corp-proxy:8080""#).unwrap();
        let c = load_from_path(f.path()).unwrap();
        let ep = c.upstream.endpoint().unwrap().unwrap();
        assert_eq!(ep.host, "corp-proxy");
        assert_eq!(ep.port, 8080);
    }

    #[test]
    fn malformed_upstream_proxy_fails_at_load() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, r#"[upstream]"#).unwrap();
        writeln!(f, r#"proxy = "socks5://corp-proxy:1080""#).unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Proxy(_)), "got: {err:?}");
    }
}
