use http::{Request, Response};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::future::Future;
use tokio_rustls::server::TlsStream;

pub type BoxBody = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, std::io::Error>;

pub async fn serve_tls<F, Fut>(tls: TlsStream<tokio::net::TcpStream>, handler: F)
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<Response<BoxBody>, Infallible>> + Send + 'static,
{
    let io = TokioIo::new(tls);
    let svc = hyper::service::service_fn(move |req| {
        let handler = handler.clone();
        async move { handler(req).await }
    });
    let _ = auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, svc)
        .await;
}

pub async fn serve_http_plain<F, Fut>(stream: tokio::net::TcpStream, handler: F)
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<Response<BoxBody>, Infallible>> + Send + 'static,
{
    let io = TokioIo::new(stream);
    let svc = hyper::service::service_fn(move |req| {
        let handler = handler.clone();
        async move { handler(req).await }
    });
    let _ = auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, svc)
        .await;
}
