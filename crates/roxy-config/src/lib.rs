#![cfg_attr(test, allow(clippy::unwrap_used))]

mod error;
pub use error::ConfigError;

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
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct CacheConfig {
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
}

impl Default for ImpersonateConfig {
    fn default() -> Self {
        Self {
            default_profile: None,
            profiles_dir: PathBuf::from("./profiles"),
            strip_header: true,
        }
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
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
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
}
