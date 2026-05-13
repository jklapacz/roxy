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
