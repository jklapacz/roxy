use crate::blob::{blob_path, ensure_dirs, tmp_path};
use crate::index;
use async_trait::async_trait;
use futures::future::{BoxFuture, FutureExt};
use roxy_cache::{Cache, CacheError, CacheKey, CacheWriter, CachedResponse, ResponseMeta};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::File;
use tokio::io::{AsyncWrite, AsyncWriteExt};

#[derive(Clone)]
pub struct FsCache {
    cache_dir: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl FsCache {
    pub fn open(cache_dir: impl Into<PathBuf>) -> Result<Self, CacheError> {
        let cache_dir = cache_dir.into();
        std::fs::create_dir_all(&cache_dir).map_err(CacheError::Io)?;
        let conn = index::open(&cache_dir.join("index.sqlite"), &cache_dir)
            .map_err(|e| CacheError::Backend(e.to_string()))?;
        ensure_dirs(&cache_dir).map_err(CacheError::Io)?;
        Ok(Self {
            cache_dir,
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Remove any leftover tmp files (called at startup).
    pub fn cleanup_tmp(&self) -> std::io::Result<usize> {
        let dir = self.cache_dir.join("tmp");
        let mut n = 0;
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let _ = std::fs::remove_file(entry.path());
                n += 1;
            }
        }
        Ok(n)
    }
}

pub struct FsWriter {
    tmp_path: PathBuf,
    file: Option<File>,
    hasher: Sha256,
    #[allow(dead_code)] // reserved for telemetry; updated on each write
    bytes_written: u64,
    key: CacheKey,
    meta: ResponseMeta,
    ttl: Duration,
    cache_dir: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

fn closed_err() -> io::Error {
    io::Error::other("FsWriter file already closed")
}

impl AsyncWrite for FsWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // SAFETY-equivalent: project the fields manually. We split the borrow so
        // `hasher` and `bytes_written` can be updated while `file` is pinned.
        let this = self.get_mut();
        let file = match this.file.as_mut() {
            Some(f) => f,
            None => return Poll::Ready(Err(closed_err())),
        };
        match Pin::new(file).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.hasher.update(&buf[..n]);
                this.bytes_written += n as u64;
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let file = match this.file.as_mut() {
            Some(f) => f,
            None => return Poll::Ready(Err(closed_err())),
        };
        Pin::new(file).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let file = match this.file.as_mut() {
            Some(f) => f,
            None => return Poll::Ready(Err(closed_err())),
        };
        Pin::new(file).poll_shutdown(cx)
    }
}

impl CacheWriter for FsWriter {
    fn finish(mut self: Box<Self>) -> BoxFuture<'static, Result<(), CacheError>> {
        async move {
            if let Some(mut f) = self.file.take() {
                f.flush().await.map_err(CacheError::Io)?;
                f.sync_all().await.map_err(CacheError::Io)?;
            }
            let hash = self.hasher.finalize();
            let hex = hex::encode(hash);
            let final_path = blob_path(&self.cache_dir, &hex);
            if let Some(parent) = final_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(CacheError::Io)?;
            }
            tokio::fs::rename(&self.tmp_path, &final_path)
                .await
                .map_err(CacheError::Io)?;

            let headers_json = serde_json::to_string(&self.meta.headers)
                .map_err(|e| CacheError::Backend(e.to_string()))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs() as i64;
            let conn = self
                .conn
                .lock()
                .map_err(|_| CacheError::Backend("index mutex poisoned".into()))?;
            conn.execute(
                "INSERT OR REPLACE INTO entries
                   (key, vary_selector, vary_headers, content_hash, status, headers_json, created_at, ttl_seconds)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    self.key.as_bytes(),
                    Vec::<u8>::new(),    // empty selector (real selector lands in Task 5)
                    Option::<String>::None,
                    hash.as_slice(),
                    self.meta.status as i64,
                    headers_json,
                    now,
                    self.ttl.as_secs() as i64,
                ],
            )
            .map_err(|e| CacheError::Backend(e.to_string()))?;
            Ok(())
        }
        .boxed()
    }

    fn abort(mut self: Box<Self>) {
        self.file.take();
        let _ = std::fs::remove_file(&self.tmp_path);
    }
}

#[async_trait]
impl Cache for FsCache {
    async fn lookup(&self, key: &CacheKey) -> Result<Option<CachedResponse>, CacheError> {
        use futures::StreamExt;
        let row = {
            let conn = self
                .conn
                .lock()
                .map_err(|_| CacheError::Backend("mutex".into()))?;
            conn.query_row(
                "SELECT content_hash, status, headers_json, created_at, ttl_seconds
                 FROM entries WHERE key = ?1 AND vary_selector = ?2",
                rusqlite::params![key.as_bytes(), Vec::<u8>::new()],
                |r| {
                    let content_hash: Vec<u8> = r.get(0)?;
                    let status: i64 = r.get(1)?;
                    let headers_json: String = r.get(2)?;
                    let created_at: i64 = r.get(3)?;
                    let ttl_seconds: i64 = r.get(4)?;
                    Ok((content_hash, status, headers_json, created_at, ttl_seconds))
                },
            )
            .ok()
        };
        let Some((content_hash, status, headers_json, created_at, ttl_seconds)) = row else {
            return Ok(None);
        };
        let hex = hex::encode(&content_hash);
        let path = blob_path(&self.cache_dir, &hex);
        let file = tokio::fs::File::open(&path).await.map_err(CacheError::Io)?;
        let reader = tokio_util::io::ReaderStream::new(file);
        let body: futures::stream::BoxStream<'static, Result<bytes::Bytes, std::io::Error>> =
            reader.boxed();

        let headers: Vec<(String, Vec<u8>)> = serde_json::from_str(&headers_json)
            .map_err(|e| CacheError::Corrupted(e.to_string()))?;

        let created = SystemTime::UNIX_EPOCH + Duration::from_secs(created_at as u64);
        let ttl = Duration::from_secs(ttl_seconds as u64);
        let resp = CachedResponse {
            meta: ResponseMeta {
                status: status as u16,
                headers,
            },
            body,
            created_at: created,
            ttl,
        };
        if resp.is_expired(SystemTime::now()) {
            return Ok(None);
        }
        Ok(Some(resp))
    }

    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
        default_ttl: Duration,
    ) -> Result<Box<dyn CacheWriter>, CacheError> {
        let tmp = tmp_path(&self.cache_dir);
        if let Some(parent) = tmp.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(CacheError::Io)?;
        }
        let file = File::create(&tmp).await.map_err(CacheError::Io)?;
        Ok(Box::new(FsWriter {
            tmp_path: tmp,
            file: Some(file),
            hasher: Sha256::new(),
            bytes_written: 0,
            key: key.clone(),
            meta,
            ttl: default_ttl,
            cache_dir: self.cache_dir.clone(),
            conn: self.conn.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn store_writes_blob_and_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);
        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![],
                },
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        w.write_all(b"hello").await.unwrap();
        w.finish().await.unwrap();

        // a blob file should now exist somewhere under blobs/
        let blobs_root = dir.path().join("blobs");
        let mut found = false;
        for prefix in std::fs::read_dir(&blobs_root).unwrap() {
            for f in std::fs::read_dir(prefix.unwrap().path()).unwrap() {
                let f = f.unwrap();
                if f.path().extension().and_then(|s| s.to_str()) == Some("bin") {
                    let bytes = std::fs::read(f.path()).unwrap();
                    assert_eq!(bytes, b"hello");
                    found = true;
                }
            }
        }
        assert!(found);
    }

    #[tokio::test]
    async fn abort_discards_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);
        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![],
                },
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        w.write_all(b"partial").await.unwrap();
        w.abort();
        assert_eq!(
            std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
            0
        );
        let blobs_root = dir.path().join("blobs");
        let n = std::fs::read_dir(&blobs_root)
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(n, 0);
    }

    use futures::StreamExt;

    async fn drain_body(
        mut s: futures::stream::BoxStream<'static, Result<bytes::Bytes, std::io::Error>>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = s.next().await {
            out.extend_from_slice(&chunk.unwrap());
        }
        out
    }

    #[tokio::test]
    async fn round_trip_store_then_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);
        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![("x".to_string(), b"y".to_vec())],
                },
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        w.write_all(b"payload").await.unwrap();
        w.finish().await.unwrap();

        let hit = cache.lookup(&key).await.unwrap().unwrap();
        assert_eq!(hit.meta.status, 200);
        assert_eq!(hit.meta.headers, vec![("x".to_string(), b"y".to_vec())]);
        let bytes = drain_body(hit.body).await;
        assert_eq!(bytes, b"payload");
    }

    #[tokio::test]
    async fn ttl_zero_means_immediately_expired() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);
        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![],
                },
                Duration::from_secs(0),
            )
            .await
            .unwrap();
        w.write_all(b"x").await.unwrap();
        w.finish().await.unwrap();
        // Sleep 1ms to guarantee elapsed > 0.
        tokio::time::sleep(Duration::from_millis(2)).await;
        let hit = cache.lookup(&key).await.unwrap();
        assert!(hit.is_none(), "expired entries must look like a miss");
    }
}
