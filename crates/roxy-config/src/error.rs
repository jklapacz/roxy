use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(std::path::PathBuf),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("path expansion: {0}")]
    Expand(String),

    #[error("upstream proxy config: {0}")]
    Proxy(String),
}
