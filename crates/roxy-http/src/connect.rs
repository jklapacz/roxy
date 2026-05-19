use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Cap on the total bytes we'll read while parsing a CONNECT request, to
/// keep a misbehaving client from forcing unbounded growth.
const MAX_CONNECT_HEADERS_BYTES: usize = 8 * 1024;

/// Parse the initial HTTP/1.1 CONNECT line off a fresh client socket.
/// Returns Ok(Some(host)) on a CONNECT, Ok(None) on any other method.
///
/// Reads one byte at a time from the socket and stops the moment the buffer
/// ends in `\r\n\r\n` — i.e. the end of the request headers. This is
/// deliberately not a `BufReader<&mut TcpStream>` because that would buffer
/// up to its capacity (8 KiB) on the first read, and any bytes a pipelined
/// client wrote after the headers would be silently discarded when the
/// BufReader is dropped at function exit. Byte-by-byte is slow in the
/// abstract but a CONNECT request is well under 1 KiB and only happens once
/// per connection, so the cost is irrelevant; correctness is what matters
/// here.
pub async fn read_connect(stream: &mut TcpStream) -> std::io::Result<Option<String>> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before end of CONNECT headers",
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() >= MAX_CONNECT_HEADERS_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CONNECT headers exceeded size limit",
            ));
        }
    }

    // First line ends at the first \r\n. By the loop's exit condition
    // the buffer ends in \r\n\r\n, so at least one \r\n is guaranteed —
    // but we still handle the missing case defensively rather than panic.
    let line_end = match buf.windows(2).position(|w| w == b"\r\n") {
        Some(i) => i,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no request line terminator in CONNECT headers",
            ))
        }
    };
    let request_line = std::str::from_utf8(&buf[..line_end])
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if !request_line.starts_with("CONNECT ") {
        return Ok(None);
    }
    let authority = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_string();
    Ok(Some(authority))
}

pub async fn write_200(stream: &mut TcpStream) -> std::io::Result<()> {
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
}
