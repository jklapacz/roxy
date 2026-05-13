use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImpersonateError {
    #[error("unknown fingerprint: {0}")]
    UnknownFingerprint(String),

    #[error("wreq: {0}")]
    Wreq(#[from] wreq::Error),

    #[error("custom profile load failed at {path}: {source}")]
    CustomLoad {
        path: std::path::PathBuf,
        #[source]
        source: anyhow::Error,
    },

    #[error("collect request body: {0}")]
    RequestBodyCollect(#[source] anyhow::Error),
}
