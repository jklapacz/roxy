use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Parse the initial HTTP/1.1 CONNECT line off a fresh client socket.
/// Returns Ok(Some(host)) on a CONNECT, Ok(None) on any other method.
///
/// FIXME(post-MVP): Uses BufReader<&mut TcpStream> which discards any
/// read-ahead bytes when dropped. Conforming clients wait for the 200
/// response before sending more data on the inner stream, so this is
/// safe for MVP. A misbehaving client pipelining a TLS ClientHello
/// immediately after the CONNECT headers could lose bytes here.
pub async fn read_connect(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let line = line.trim_end_matches(['\r', '\n']);
    if !line.starts_with("CONNECT ") {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let _ = parts.next(); // CONNECT
    let authority = parts.next().unwrap_or("").to_string();
    // Drain remaining headers up to empty line.
    loop {
        let mut hl = String::new();
        let n = reader.read_line(&mut hl).await?;
        if n == 0 || hl == "\r\n" || hl == "\n" {
            break;
        }
    }
    Ok(Some(authority))
}

pub async fn write_200(stream: &mut TcpStream) -> std::io::Result<()> {
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
}
