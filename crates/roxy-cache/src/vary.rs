//! Variant selector hashing for response `Vary` headers. The selector is
//! the SHA-256 of a stable encoding of `(header-name, header-value)` pairs
//! for the request headers named in the response's `Vary`. When the
//! response had no `Vary`, the selector is the empty byte slice — so
//! no-Vary entries collide only with other no-Vary entries for the same
//! base key.

use sha2::{Digest, Sha256};

pub type ReqHeaders = [(String, Vec<u8>)];

/// Compute a 32-byte variant selector for the request headers named in the
/// response's `Vary`. Returns an empty `Vec` when `vary` is `None` or empty
/// (so no-Vary entries collide only with other no-Vary entries).
///
/// Algorithm: split `vary` on `,`, trim and lowercase each name, drop
/// empties and any `*` token (Vary: * is filtered out upstream). Sort the
/// names ASCII-ascending. For each name, gather every matching request
/// header value (case-insensitive name compare) joined by ASCII comma. A
/// missing request header contributes an empty value. Encode as
/// `name\0value\0name\0value\0…` and SHA-256-hash the encoding.
pub fn compute_selector(vary: Option<&str>, req_headers: &ReqHeaders) -> Vec<u8> {
    let Some(vary) = vary else {
        return Vec::new();
    };
    let mut names: Vec<String> = vary
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != "*")
        .collect();
    if names.is_empty() {
        return Vec::new();
    }
    names.sort();
    names.dedup();

    let mut hasher = Sha256::new();
    for name in &names {
        hasher.update(name.as_bytes());
        hasher.update([0u8]);

        let mut first = true;
        for (req_name, req_value) in req_headers {
            if req_name.eq_ignore_ascii_case(name) {
                if !first {
                    hasher.update(b",");
                }
                hasher.update(req_value);
                first = false;
            }
        }
        hasher.update([0u8]);
    }
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_vec()))
            .collect()
    }

    #[test]
    fn no_vary_yields_empty_selector() {
        assert!(compute_selector(None, &[]).is_empty());
        assert!(compute_selector(Some("   "), &[]).is_empty());
        assert!(compute_selector(Some(""), &[]).is_empty());
    }

    #[test]
    fn same_headers_same_selector() {
        let req = pairs(&[("accept", b"application/json")]);
        let a = compute_selector(Some("Accept"), &req);
        let b = compute_selector(Some("Accept"), &req);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn different_values_differ() {
        let json = pairs(&[("accept", b"application/json")]);
        let html = pairs(&[("accept", b"text/html")]);
        assert_ne!(
            compute_selector(Some("Accept"), &json),
            compute_selector(Some("Accept"), &html)
        );
    }

    #[test]
    fn vary_name_case_insensitive() {
        let lower = pairs(&[("accept", b"application/json")]);
        let upper = pairs(&[("Accept", b"application/json")]);
        assert_eq!(
            compute_selector(Some("Accept"), &lower),
            compute_selector(Some("accept"), &upper),
        );
    }

    #[test]
    fn missing_request_header_is_empty_value() {
        // Both requests are missing the Vary'd header, so they should collide.
        let a = compute_selector(Some("Accept-Encoding"), &[]);
        let b = compute_selector(Some("Accept-Encoding"), &pairs(&[("user-agent", b"x")]));
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // A present header should produce a different selector than absent.
        let c = compute_selector(
            Some("Accept-Encoding"),
            &pairs(&[("accept-encoding", b"gzip")]),
        );
        assert_ne!(a, c);
    }

    #[test]
    fn comma_separated_and_multi_value_equivalent() {
        let req = pairs(&[
            ("accept", b"application/json"),
            ("accept-encoding", b"gzip"),
        ]);
        let combined = compute_selector(Some("Accept, Accept-Encoding"), &req);
        let with_spaces = compute_selector(Some(" Accept , Accept-Encoding "), &req);
        assert_eq!(combined, with_spaces);
    }

    #[test]
    fn vary_names_sorted_before_hashing() {
        let req = pairs(&[("a", b"1"), ("b", b"2")]);
        assert_eq!(
            compute_selector(Some("A, B"), &req),
            compute_selector(Some("B, A"), &req)
        );
    }

    #[test]
    fn multiple_request_values_for_same_header_join_with_comma() {
        // If the request slice carries the same Vary'd header twice (multi-value
        // header), both contribute to the selector. The function joins them in
        // slice order with a comma so duplicates are not silently dropped.
        let one = pairs(&[("accept", b"application/json")]);
        let two = pairs(&[("accept", b"application/json"), ("accept", b"text/html")]);
        assert_ne!(
            compute_selector(Some("Accept"), &one),
            compute_selector(Some("Accept"), &two)
        );
    }
}
