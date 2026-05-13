use bytes::Bytes;
use futures::Stream;
use http_body::{Body, Frame};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    /// `http_body::Body` adapter over `wreq::Response::bytes_stream()`. Errors
    /// from wreq are surfaced as `io::Error::other(...)` to match the existing
    /// upstream error shape (`hyper::body::Incoming` is mapped the same way in
    /// `UpstreamBody`).
    pub struct ImpersonateBody {
        #[pin]
        inner: futures::stream::BoxStream<'static, Result<Bytes, wreq::Error>>,
    }
}

impl ImpersonateBody {
    pub fn from_response(resp: wreq::Response) -> Self {
        use futures::StreamExt;
        Self {
            inner: resp.bytes_stream().boxed(),
        }
    }
}

impl Body for ImpersonateBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let this = self.project();
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(Frame::data(b)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(std::io::Error::other(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    /// Smoke test: hit a real endpoint, drain through ImpersonateBody.
    /// `#[ignore]` because it requires network.
    #[tokio::test]
    #[ignore]
    async fn drains_real_response() {
        let client = wreq::Client::builder()
            .emulation(wreq_util::Emulation::Chrome137)
            .build()
            .unwrap();
        let resp = client
            .get("https://httpbin.org/bytes/64")
            .send()
            .await
            .unwrap();
        let body = ImpersonateBody::from_response(resp);
        let collected = body.collect().await.unwrap().to_bytes();
        assert_eq!(collected.len(), 64);
    }
}
