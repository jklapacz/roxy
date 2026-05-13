use bytes::Bytes;
use futures::stream::BoxStream;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct ResponseMeta {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
}

pub struct CachedResponse {
    pub meta: ResponseMeta,
    pub body: BoxStream<'static, Result<Bytes, std::io::Error>>,
    pub created_at: SystemTime,
    pub ttl: Duration,
}

impl CachedResponse {
    pub fn is_expired(&self, now: SystemTime) -> bool {
        match now.duration_since(self.created_at) {
            Ok(age) => age >= self.ttl,
            Err(_) => false,
        }
    }
}
