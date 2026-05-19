#![allow(clippy::unwrap_used)]

use roxy_http::connect::{read_connect, write_200};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn connect_parsed_and_acknowledged() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let host = read_connect(&mut s).await.unwrap().unwrap();
        assert_eq!(host, "example.com:443");
        write_200(&mut s).await.unwrap();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let n = client.read(&mut buf).await.unwrap();
    let resp = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "got: {resp}");
}

/// Regression: a misbehaving / pipelined client may write payload bytes
/// immediately after the CONNECT headers, before waiting for the 200. The
/// previous BufReader<&mut TcpStream> implementation buffered up to 8 KiB
/// on its first read, swallowing those bytes when the BufReader was dropped.
/// `read_connect` must consume only the CONNECT request line + headers
/// (through `\r\n\r\n`) and leave anything after that on the socket.
#[tokio::test]
async fn read_connect_does_not_consume_pipelined_bytes() {
    use std::time::Duration;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let host = read_connect(&mut s).await.unwrap().unwrap();
        assert_eq!(host, "example.com:443");
        // Read the bytes the client pipelined after the headers directly
        // off the same socket — read_connect must not have eaten them.
        let mut tail = [0u8; 17];
        s.read_exact(&mut tail).await.unwrap();
        tail
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\n\
              Host: example.com:443\r\n\
              \r\n\
              PIPELINED-PAYLOAD",
        )
        .await
        .unwrap();

    let outcome = tokio::time::timeout(Duration::from_secs(2), server).await;
    assert!(
        outcome.is_ok(),
        "read_connect ate the pipelined bytes — server is blocked on read_exact"
    );
    let tail = outcome.unwrap().unwrap();
    assert_eq!(&tail, b"PIPELINED-PAYLOAD");
}
