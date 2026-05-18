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
    vary_selector: Vec<u8>,
    vary_headers: Option<String>,
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
                    self.vary_selector.clone(),
                    self.vary_headers.clone(),
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
    async fn lookup(
        &self,
        key: &CacheKey,
        req_headers: &roxy_cache::ReqHeaders,
    ) -> Result<Option<CachedResponse>, CacheError> {
        use futures::StreamExt;
        let candidates: Vec<(Vec<u8>, Option<String>, Vec<u8>, i64, String, i64, i64)> = {
            let conn = self
                .conn
                .lock()
                .map_err(|_| CacheError::Backend("mutex".into()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT vary_selector, vary_headers, content_hash, status, headers_json, created_at, ttl_seconds
                     FROM entries WHERE key = ?1
                     ORDER BY CASE WHEN vary_headers IS NULL THEN 1 ELSE 0 END",
                )
                .map_err(|e| CacheError::Backend(e.to_string()))?;
            let rows = stmt
                .query_map([key.as_bytes()], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, i64>(6)?,
                    ))
                })
                .map_err(|e| CacheError::Backend(e.to_string()))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| CacheError::Backend(e.to_string()))?);
            }
            out
        };

        for (
            vary_selector,
            vary_headers,
            content_hash,
            status,
            headers_json,
            created_at,
            ttl_seconds,
        ) in candidates
        {
            let expected = roxy_cache::compute_selector(vary_headers.as_deref(), req_headers);
            if expected != vary_selector {
                continue;
            }
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
                continue;
            }
            return Ok(Some(resp));
        }
        Ok(None)
    }

    async fn begin_store(
        &self,
        key: &CacheKey,
        meta: ResponseMeta,
        default_ttl: Duration,
        req_headers: &roxy_cache::ReqHeaders,
    ) -> Result<Box<dyn CacheWriter>, CacheError> {
        let tmp = tmp_path(&self.cache_dir);
        if let Some(parent) = tmp.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(CacheError::Io)?;
        }
        let file = File::create(&tmp).await.map_err(CacheError::Io)?;
        let vary_headers = meta
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("vary"))
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
            .map(|s| s.to_string());
        let vary_selector = roxy_cache::compute_selector(vary_headers.as_deref(), req_headers);
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
            vary_selector,
            vary_headers,
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
                &[],
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
                &[],
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
                &[],
            )
            .await
            .unwrap();
        w.write_all(b"payload").await.unwrap();
        w.finish().await.unwrap();

        let hit = cache.lookup(&key, &[]).await.unwrap().unwrap();
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
                &[],
            )
            .await
            .unwrap();
        w.write_all(b"x").await.unwrap();
        w.finish().await.unwrap();
        // Sleep 1ms to guarantee elapsed > 0.
        tokio::time::sleep(Duration::from_millis(2)).await;
        let hit = cache.lookup(&key, &[]).await.unwrap();
        assert!(hit.is_none(), "expired entries must look like a miss");
    }

    fn req(headers: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect()
    }

    #[tokio::test]
    async fn vary_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);

        let json_req = req(&[("accept", b"application/json")]);
        let html_req = req(&[("accept", b"text/html")]);

        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![("vary".to_string(), b"Accept".to_vec())],
                },
                Duration::from_secs(60),
                &json_req,
            )
            .await
            .unwrap();
        w.write_all(b"json-body").await.unwrap();
        w.finish().await.unwrap();

        // Same variant: hit.
        let hit = cache.lookup(&key, &json_req).await.unwrap();
        assert!(hit.is_some(), "matching variant must hit");
        let body = drain_body(hit.unwrap().body).await;
        assert_eq!(body, b"json-body");

        // Different variant: miss.
        let miss = cache.lookup(&key, &html_req).await.unwrap();
        assert!(miss.is_none(), "different Accept value must miss");
    }

    #[tokio::test]
    async fn two_variants_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);
        let json_req = req(&[("accept", b"application/json")]);
        let html_req = req(&[("accept", b"text/html")]);

        for (req_hdrs, body) in [
            (&json_req, &b"json-body"[..]),
            (&html_req, &b"html-body"[..]),
        ] {
            let mut w = cache
                .begin_store(
                    &key,
                    ResponseMeta {
                        status: 200,
                        headers: vec![("vary".to_string(), b"Accept".to_vec())],
                    },
                    Duration::from_secs(60),
                    req_hdrs,
                )
                .await
                .unwrap();
            w.write_all(body).await.unwrap();
            w.finish().await.unwrap();
        }

        let json_body =
            drain_body(cache.lookup(&key, &json_req).await.unwrap().unwrap().body).await;
        let html_body =
            drain_body(cache.lookup(&key, &html_req).await.unwrap().unwrap().body).await;
        assert_eq!(json_body, b"json-body");
        assert_eq!(html_body, b"html-body");
    }

    #[tokio::test]
    async fn no_vary_and_vary_can_coexist_under_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let cache = FsCache::open(dir.path()).unwrap();
        let key = CacheKey::from_parts("_default", "GET", "https", "x.y", "/p", None);

        // No-Vary entry.
        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![],
                },
                Duration::from_secs(60),
                &[],
            )
            .await
            .unwrap();
        w.write_all(b"default-body").await.unwrap();
        w.finish().await.unwrap();

        // Vary entry under the same base key.
        let json_req = req(&[("accept", b"application/json")]);
        let mut w = cache
            .begin_store(
                &key,
                ResponseMeta {
                    status: 200,
                    headers: vec![("vary".to_string(), b"Accept".to_vec())],
                },
                Duration::from_secs(60),
                &json_req,
            )
            .await
            .unwrap();
        w.write_all(b"json-body").await.unwrap();
        w.finish().await.unwrap();

        // Request with no Accept hits the no-Vary entry.
        let default_hit = cache.lookup(&key, &[]).await.unwrap().unwrap();
        assert_eq!(drain_body(default_hit.body).await, b"default-body");

        // Request matching the variant hits the variant.
        let variant_hit = cache.lookup(&key, &json_req).await.unwrap().unwrap();
        assert_eq!(drain_body(variant_hit.body).await, b"json-body");
    }
}
