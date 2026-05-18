use bytes::Bytes;
use futures::stream::BoxStream;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct ResponseMeta {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
}

/// A cache hit: response metadata plus a streaming body.
///
/// `created_at` and `ttl` together define the freshness window. Backends are
/// expected to populate `created_at` from their own stored metadata (e.g. the
/// `created_at` column in the sqlite index), not from `SystemTime::now()` at
/// lookup time — the point of caching this is that staleness is computed
/// against the moment of storage, not the moment of read.
pub struct CachedResponse {
    pub meta: ResponseMeta,
    pub body: BoxStream<'static, Result<Bytes, std::io::Error>>,
    pub created_at: SystemTime,
    pub ttl: Duration,
}

impl CachedResponse {
    /// Returns `true` when `now - created_at >= ttl`.
    ///
    /// Clock-skew policy: if `now < created_at` (clock moved backwards, or the
    /// entry was written by a host with a faster clock), this returns `false`.
    /// We trust the stored `created_at` over the wall clock — treating a
    /// backwards-skewed read as "instantly expired" would cause spurious misses
    /// every time NTP drifts or the laptop sleeps. The downside is that an
    /// entry written under a forward-skewed clock will appear fresh for longer
    /// than its true TTL, which we accept.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        match now.duration_since(self.created_at) {
            Ok(age) => age >= self.ttl,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    fn empty_body() -> BoxStream<'static, Result<Bytes, std::io::Error>> {
        Box::pin(stream::empty())
    }

    fn make(created_at: SystemTime, ttl: Duration) -> CachedResponse {
        CachedResponse {
            meta: ResponseMeta {
                status: 200,
                headers: vec![],
            },
            body: empty_body(),
            created_at,
            ttl,
        }
    }

    #[test]
    fn zero_ttl_is_expired_at_or_after_creation() {
        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let resp = make(created, Duration::ZERO);
        assert!(resp.is_expired(created), "age == 0, ttl == 0 must expire");
        assert!(resp.is_expired(created + Duration::from_millis(1)));
    }

    #[test]
    fn exact_boundary_is_expired() {
        // age == ttl is the boundary: spec says `>= ttl` expires.
        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let ttl = Duration::from_secs(60);
        let resp = make(created, ttl);
        assert!(!resp.is_expired(created + ttl - Duration::from_nanos(1)));
        assert!(resp.is_expired(created + ttl));
    }

    #[test]
    fn future_created_at_is_not_expired() {
        // Clock skew: stored entry claims it was created in the future.
        // Policy is to trust the stored metadata and treat it as fresh.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let resp = make(now + Duration::from_secs(60), Duration::from_secs(10));
        assert!(!resp.is_expired(now));
    }
}
