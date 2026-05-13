#![cfg_attr(test, allow(clippy::unwrap_used))]

mod error;
mod key;
mod response;

pub use error::CacheError;
pub use key::CacheKey;
pub use response::{CachedResponse, ResponseMeta};

use async_trait::async_trait;
use futures::future::BoxFuture;
use tokio::io::AsyncWrite;

#[async_trait]
pub trait Cache: Send + Sync {
    async fn lookup(&self, key: &CacheKey) -> Result<Option<CachedResponse>, CacheError>;

    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
        default_ttl: std::time::Duration,
    ) -> Result<Box<dyn CacheWriter>, CacheError>;
}

pub trait CacheWriter: AsyncWrite + Send + Unpin {
    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(), CacheError>>;
    fn abort(self: Box<Self>);
}
