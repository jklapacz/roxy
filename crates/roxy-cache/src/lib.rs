#![cfg_attr(test, allow(clippy::unwrap_used))]

mod error;
mod key;
mod response;
mod vary;

pub use error::CacheError;
pub use key::CacheKey;
pub use response::{CachedResponse, ResponseMeta};
pub use vary::{compute_selector, ReqHeaders};

use async_trait::async_trait;
use futures::future::BoxFuture;
use tokio::io::AsyncWrite;

#[async_trait]
pub trait Cache: Send + Sync {
    async fn lookup(
        &self,
        key: &CacheKey,
        req_headers: &vary::ReqHeaders,
    ) -> Result<Option<CachedResponse>, CacheError>;

    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
        default_ttl: std::time::Duration,
        req_headers: &vary::ReqHeaders,
    ) -> Result<Box<dyn CacheWriter>, CacheError>;
}

/// Streaming write handle returned by [`Cache::begin_store`].
///
/// The `Send + Unpin` bounds (and the `Send` bound on `CachedResponse::body`
/// via [`futures::stream::BoxStream`]) exist so the writer and the cached body
/// can flow through the proxy's per-connection `tokio::spawn` tasks: bytes
/// arrive from a hyper response stream on one task and the cache write may be
/// driven on another. Anything weaker would force backends to keep work
/// pinned to a single task, which the current proxy plumbing does not do.
pub trait CacheWriter: AsyncWrite + Send + Unpin {
    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(), CacheError>>;

    /// Discard the in-flight write and free any temporary state.
    ///
    /// Called from an async context (e.g. when the upstream response stream
    /// errors mid-body), so implementations must not block for any significant
    /// amount of time. A single `std::fs::remove_file` on a tmp path is
    /// acceptable; anything heavier (fsync, network round-trips, lock
    /// contention) must be spawned onto a blocking executor.
    fn abort(self: Box<Self>);
}
