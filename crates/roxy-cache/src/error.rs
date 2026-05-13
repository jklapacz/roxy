use thiserror::Error;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("backend: {0}")]
    Backend(String),

    #[error("corrupted entry: {0}")]
    Corrupted(String),
}
