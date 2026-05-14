//! Stream adapters used by the capture server.
//!
//! [`PrefixedStream`] replays a buffered prefix (the raw ClientHello bytes,
//! read off the socket so they can be parsed) before delegating to the inner
//! stream, so the rustls acceptor still sees a complete handshake.
//!
//! [`RecordingStream`] tees every byte *read* from the inner stream into a
//! shared, capped buffer, so the decrypted HTTP/2 frames the client sends can
//! be inspected after hyper has parsed the first request.

use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum number of read bytes [`RecordingStream`] retains. Comfortably covers
/// the HTTP/2 client preface + the initial SETTINGS frame + the first request's
/// HEADERS frame.
pub const RECORD_CAP: usize = 32 * 1024;

/// Lock a mutex, recovering the guard even if a previous holder panicked. Used
/// instead of `.unwrap()` because the workspace denies `clippy::unwrap_used`.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pin_project! {
    pub struct PrefixedStream<S> {
        prefix: Vec<u8>,
        pos: usize,
        #[pin]
        inner: S,
    }
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        if *this.pos < this.prefix.len() {
            let remaining = &this.prefix[*this.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            *this.pos += n;
            return Poll::Ready(Ok(()));
        }
        this.inner.poll_read(cx, buf)
    }
}

impl<S: AsyncWrite> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

pin_project! {
    pub struct RecordingStream<S> {
        record: std::sync::Arc<Mutex<Vec<u8>>>,
        #[pin]
        inner: S,
    }
}

impl<S> RecordingStream<S> {
    pub fn new(inner: S, record: std::sync::Arc<Mutex<Vec<u8>>>) -> Self {
        Self { record, inner }
    }
}

impl<S: AsyncRead> AsyncRead for RecordingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        let before = buf.filled().len();
        let r = this.inner.poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let fresh = &buf.filled()[before..];
            if !fresh.is_empty() {
                let mut rec = lock(this.record);
                if rec.len() < RECORD_CAP {
                    let take = fresh.len().min(RECORD_CAP - rec.len());
                    rec.extend_from_slice(&fresh[..take]);
                }
            }
        }
        r
    }
}

impl<S: AsyncWrite> AsyncWrite for RecordingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn prefixed_stream_replays_prefix_then_inner() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b" world").await.unwrap();
        drop(a);
        let mut s = PrefixedStream::new(b"hello".to_vec(), b);
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn recording_stream_tees_reads() {
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"abcdef").await.unwrap();
        drop(a);
        let record = Arc::new(Mutex::new(Vec::new()));
        let mut s = RecordingStream::new(b, record.clone());
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"abcdef");
        assert_eq!(&*lock(&record), b"abcdef");
    }
}
