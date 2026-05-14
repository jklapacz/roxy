//! Parse the client's HTTP/2 fingerprint from the decrypted bytes recorded off
//! the connection.
//!
//! After the TLS handshake an HTTP/2 client sends, in order: the 24-byte
//! connection preface, a SETTINGS frame, and (for the first request) a HEADERS
//! frame. By the time hyper hands us the first `Request`, all of those bytes
//! are in the [`RecordingStream`](crate::stream::RecordingStream) buffer.
//!
//! We walk the frames to capture the SETTINGS values + their order, and
//! HPACK-decode the first HEADERS frame to recover the pseudo-header order. The
//! HPACK dynamic table starts empty on the first frame, so decoding it in
//! isolation is correct.
//!
//! Identifiers emitted here MUST match `setting_from_str` / `pseudo_from_str`
//! in `roxy-impersonate`'s `custom.rs`.

use httlib_hpack::Decoder;

/// The subset of an HTTP/2 connection that maps onto `roxy-impersonate`'s
/// `Http2Spec`.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedHttp2 {
    pub header_table_size: Option<u32>,
    pub enable_push: Option<bool>,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub enable_connect_protocol: Option<bool>,
    pub no_rfc7540_priorities: Option<bool>,
    pub settings_order: Vec<String>,
    pub header_order: Vec<String>,
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FLAG_ACK: u8 = 0x1;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// Parse recorded client→server bytes into a `CapturedHttp2`.
///
/// Returns `None` when the bytes do not start with the HTTP/2 preface (i.e. the
/// client negotiated HTTP/1.1) or no HEADERS frame was captured.
pub fn parse_http2(buf: &[u8]) -> Option<CapturedHttp2> {
    let mut cursor = buf.strip_prefix(PREFACE)?;

    // Only what the client actually sent is captured; everything starts unset.
    let mut header_table_size: Option<u32> = None;
    let mut enable_push: Option<bool> = None;
    let mut max_concurrent_streams: Option<u32> = None;
    let mut initial_window_size: Option<u32> = None;
    let mut initial_connection_window_size: Option<u32> = None;
    let mut max_frame_size: Option<u32> = None;
    let mut max_header_list_size: Option<u32> = None;
    let mut enable_connect_protocol: Option<bool> = None;
    let mut no_rfc7540_priorities: Option<bool> = None;
    let mut settings_order: Vec<String> = Vec::new();
    let mut got_settings = false;
    let mut header_order: Option<Vec<String>> = None;

    while cursor.len() >= FRAME_HEADER_LEN {
        let len = u32::from_be_bytes([0, cursor[0], cursor[1], cursor[2]]) as usize;
        let frame_type = cursor[3];
        let flags = cursor[4];
        let body_end = FRAME_HEADER_LEN + len;
        if cursor.len() < body_end {
            break; // truncated frame; stop with what we have
        }
        let body = &cursor[FRAME_HEADER_LEN..body_end];

        match frame_type {
            FRAME_SETTINGS if flags & FLAG_ACK == 0 && !got_settings => {
                for pair in body.chunks_exact(6) {
                    let id = u16::from_be_bytes([pair[0], pair[1]]);
                    let value = u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]);
                    if let Some(name) = setting_name(id) {
                        settings_order.push(name.to_string());
                    }
                    match id {
                        0x1 => header_table_size = Some(value),
                        0x2 => enable_push = Some(value != 0),
                        0x3 => max_concurrent_streams = Some(value),
                        0x4 => initial_window_size = Some(value),
                        0x5 => max_frame_size = Some(value),
                        0x6 => max_header_list_size = Some(value),
                        0x8 => enable_connect_protocol = Some(value != 0),
                        0x9 => no_rfc7540_priorities = Some(value != 0),
                        _ => {}
                    }
                }
                got_settings = true;
            }
            FRAME_HEADERS if header_order.is_none() => {
                header_order = Some(decode_pseudo_order(body, flags));
            }
            FRAME_WINDOW_UPDATE if initial_connection_window_size.is_none() => {
                let stream_id =
                    u32::from_be_bytes([cursor[5] & 0x7f, cursor[6], cursor[7], cursor[8]]);
                if stream_id == 0 && body.len() >= 4 {
                    let inc =
                        u32::from_be_bytes([body[0], body[1], body[2], body[3]]) & 0x7fff_ffff;
                    initial_connection_window_size = Some(inc);
                }
            }
            _ => {}
        }

        cursor = &cursor[body_end..];
        if got_settings && header_order.is_some() {
            break;
        }
    }

    let header_order = header_order?;
    Some(CapturedHttp2 {
        header_table_size,
        enable_push,
        max_concurrent_streams,
        initial_window_size,
        initial_connection_window_size,
        max_frame_size,
        max_header_list_size,
        enable_connect_protocol,
        no_rfc7540_priorities,
        settings_order,
        header_order,
    })
}

/// HPACK-decode a HEADERS frame body and return the pseudo-header (`:`-prefixed)
/// names in the order they appear. Padding/priority prefixes are stripped
/// first. A truncated or continued block still yields whatever decoded before
/// the cut — pseudo-headers come first, so they survive.
fn decode_pseudo_order(body: &[u8], flags: u8) -> Vec<String> {
    let mut block = body;
    let mut pad_len = 0usize;
    if flags & FLAG_PADDED != 0 {
        let Some((first, rest)) = block.split_first() else {
            return Vec::new();
        };
        pad_len = *first as usize;
        block = rest;
    }
    if flags & FLAG_PRIORITY != 0 {
        if block.len() < 5 {
            return Vec::new();
        }
        block = &block[5..]; // 4-byte stream dependency + 1-byte weight
    }
    if pad_len > block.len() {
        return Vec::new();
    }
    block = &block[..block.len() - pad_len];

    let mut decoder = Decoder::default();
    let mut input = block.to_vec();
    let mut decoded: Vec<(Vec<u8>, Vec<u8>, u8)> = Vec::new();
    // Errors on a continued/truncated block; `decoded` keeps the prefix.
    // Pseudo-headers lead the block, so they survive a CONTINUATION cut.
    let _ = decoder.decode(&mut input, &mut decoded);

    decoded
        .iter()
        .filter_map(|(name, _, _)| {
            let name = std::str::from_utf8(name).ok()?;
            name.starts_with(':').then(|| name.to_string())
        })
        .collect()
}

/// SETTINGS identifier → `custom.rs`'s `setting_from_str` identifier.
fn setting_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x1 => "HEADER_TABLE_SIZE",
        0x2 => "ENABLE_PUSH",
        0x3 => "MAX_CONCURRENT_STREAMS",
        0x4 => "INITIAL_WINDOW_SIZE",
        0x5 => "MAX_FRAME_SIZE",
        0x6 => "MAX_HEADER_LIST_SIZE",
        0x8 => "ENABLE_CONNECT_PROTOCOL",
        0x9 => "NO_RFC7540_PRIORITIES",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use httlib_hpack::Encoder;

    fn frame(frame_type: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len();
        let mut f = vec![
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            frame_type,
            flags,
            0,
            0,
            0,
            1, // stream id 1
        ];
        f.extend_from_slice(body);
        f
    }

    fn settings_body(pairs: &[(u16, u32)]) -> Vec<u8> {
        let mut b = Vec::new();
        for (id, val) in pairs {
            b.extend_from_slice(&id.to_be_bytes());
            b.extend_from_slice(&val.to_be_bytes());
        }
        b
    }

    fn hpack_block(headers: &[(&str, &str)]) -> Vec<u8> {
        let mut encoder = Encoder::default();
        let mut dst = Vec::new();
        for (name, value) in headers {
            encoder
                .encode(
                    (name.as_bytes().to_vec(), value.as_bytes().to_vec(), 0x10),
                    &mut dst,
                )
                .unwrap();
        }
        dst
    }

    #[test]
    fn returns_none_without_preface() {
        assert!(parse_http2(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn parses_settings_and_pseudo_header_order() {
        let mut buf = Vec::new();
        buf.extend_from_slice(PREFACE);
        buf.extend_from_slice(&frame(
            FRAME_SETTINGS,
            0,
            &settings_body(&[(0x1, 65536), (0x2, 0), (0x4, 6291456), (0x6, 262144)]),
        ));
        buf.extend_from_slice(&frame(
            FRAME_HEADERS,
            0x4,
            &hpack_block(&[
                (":method", "GET"),
                (":authority", "example.com"),
                (":scheme", "https"),
                (":path", "/"),
            ]),
        ));
        let h2 = parse_http2(&buf).expect("should parse");
        assert_eq!(h2.header_table_size, Some(65536));
        assert_eq!(h2.enable_push, Some(false));
        assert_eq!(h2.initial_window_size, Some(6291456));
        assert_eq!(h2.max_header_list_size, Some(262144));
        assert_eq!(h2.max_frame_size, None); // not sent — must not be emitted
        assert_eq!(
            h2.settings_order,
            vec![
                "HEADER_TABLE_SIZE",
                "ENABLE_PUSH",
                "INITIAL_WINDOW_SIZE",
                "MAX_HEADER_LIST_SIZE"
            ]
        );
        assert_eq!(
            h2.header_order,
            vec![":method", ":authority", ":scheme", ":path"]
        );
    }

    #[test]
    fn captures_connection_window_update() {
        let mut buf = Vec::new();
        buf.extend_from_slice(PREFACE);
        buf.extend_from_slice(&frame(FRAME_SETTINGS, 0, &settings_body(&[(0x2, 0)])));
        // WINDOW_UPDATE frame, stream 0, increment 15663105 (0x00EF0001).
        let mut wu = vec![0, 0, 4, 0x8, 0, 0, 0, 0, 0];
        wu.extend_from_slice(&15663105u32.to_be_bytes());
        buf.extend_from_slice(&wu);
        buf.extend_from_slice(&frame(
            FRAME_HEADERS,
            0x4,
            &hpack_block(&[(":method", "GET")]),
        ));
        let h2 = parse_http2(&buf).expect("should parse");
        assert_eq!(h2.initial_connection_window_size, Some(15663105));
    }

    #[test]
    fn handles_padded_and_priority_headers_flags() {
        let block = hpack_block(&[(":method", "GET"), (":path", "/")]);
        let mut body = Vec::new();
        body.push(3u8); // pad length
        body.extend_from_slice(&[0, 0, 0, 0, 9]); // priority: dependency + weight
        body.extend_from_slice(&block);
        body.extend_from_slice(&[0, 0, 0]); // padding

        let order = decode_pseudo_order(&body, FLAG_PADDED | FLAG_PRIORITY);
        assert_eq!(order, vec![":method", ":path"]);
    }
}
