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

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            cache: CacheConfig::default(),
            ca: CaConfig::default(),
            log: LogConfig::default(),
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
}
