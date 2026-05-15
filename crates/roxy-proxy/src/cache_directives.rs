//! Parsing of response `Cache-Control` directives that affect roxy's caching
//! decision. Only the directives roxy currently honors are surfaced:
//!
//! - `no-store`, `private` — suppress caching entirely
//! - `max-age=N` — override the configured default TTL
//!
//! Other directives (`no-cache`, `must-revalidate`, `s-maxage`, …) are
//! parsed-but-ignored — roxy has no revalidation pipeline yet, so honoring
//! them would change semantics without the supporting machinery. When that
//! machinery lands, extend `CacheDirectives` rather than reparsing here.

use std::time::Duration;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CacheDirectives {
    pub no_store: bool,
    pub private: bool,
    pub max_age: Option<Duration>,
}

impl CacheDirectives {
    /// Whether the response may be stored at all. False if `no-store` or
    /// `private` is present — roxy is a shared cache by construction
    /// (multiple users share one process) so `private` responses are
    /// non-storable.
    pub fn should_cache(&self) -> bool {
        !self.no_store && !self.private
    }

    /// TTL to use when storing this response: `max-age` if present,
    /// otherwise the caller-supplied default.
    pub fn effective_ttl(&self, default: Duration) -> Duration {
        self.max_age.unwrap_or(default)
    }
}

/// Parse all `Cache-Control` response headers. Handles multiple header lines
/// and comma-separated directives within a single line per RFC 9111 §5.2.
pub fn parse(headers: &http::HeaderMap) -> CacheDirectives {
    let mut out = CacheDirectives::default();
    for value in headers.get_all(http::header::CACHE_CONTROL).iter() {
        let s = match value.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        for raw in s.split(',') {
            apply_directive(&mut out, raw.trim());
        }
    }
    out
}

fn apply_directive(out: &mut CacheDirectives, raw: &str) {
    if raw.is_empty() {
        return;
    }
    let (name, value) = match raw.split_once('=') {
        Some((n, v)) => (n.trim(), Some(unquote(v.trim()))),
        None => (raw, None),
    };
    if name.eq_ignore_ascii_case("no-store") {
        out.no_store = true;
    } else if name.eq_ignore_ascii_case("private") {
        out.private = true;
    } else if name.eq_ignore_ascii_case("max-age") {
        if let Some(v) = value {
            if let Ok(secs) = v.parse::<u64>() {
                out.max_age = Some(Duration::from_secs(secs));
            }
        }
    }
}

fn unquote(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdrs(values: &[&str]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for v in values {
            h.append(
                http::header::CACHE_CONTROL,
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn no_header_is_default() {
        let d = parse(&http::HeaderMap::new());
        assert_eq!(d, CacheDirectives::default());
        assert!(d.should_cache());
        assert_eq!(
            d.effective_ttl(Duration::from_secs(60)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn no_store_blocks_caching() {
        let d = parse(&hdrs(&["no-store"]));
        assert!(d.no_store);
        assert!(!d.should_cache());
    }

    #[test]
    fn private_blocks_caching() {
        let d = parse(&hdrs(&["private"]));
        assert!(d.private);
        assert!(!d.should_cache());
    }

    #[test]
    fn max_age_sets_ttl() {
        let d = parse(&hdrs(&["max-age=120"]));
        assert_eq!(d.max_age, Some(Duration::from_secs(120)));
        assert_eq!(
            d.effective_ttl(Duration::from_secs(60)),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn max_age_zero_is_honored_as_uncacheable_ttl() {
        // max-age=0 is a valid value meaning "stale immediately"; roxy stores
        // it as Duration::ZERO and the cache layer's expiry check handles it.
        let d = parse(&hdrs(&["max-age=0"]));
        assert_eq!(d.max_age, Some(Duration::ZERO));
        assert_eq!(d.effective_ttl(Duration::from_secs(60)), Duration::ZERO);
    }

    #[test]
    fn comma_separated_directives_in_one_header() {
        let d = parse(&hdrs(&["private, max-age=30, no-store"]));
        assert!(d.no_store);
        assert!(d.private);
        assert_eq!(d.max_age, Some(Duration::from_secs(30)));
        assert!(!d.should_cache());
    }

    #[test]
    fn multiple_header_lines_combined() {
        let d = parse(&hdrs(&["max-age=10", "no-store"]));
        assert!(d.no_store);
        assert_eq!(d.max_age, Some(Duration::from_secs(10)));
    }

    #[test]
    fn case_insensitive_directive_names() {
        let d = parse(&hdrs(&["No-Store", "MAX-AGE=5", "Private"]));
        assert!(d.no_store);
        assert!(d.private);
        assert_eq!(d.max_age, Some(Duration::from_secs(5)));
    }

    #[test]
    fn quoted_max_age_value_accepted() {
        // RFC 9111 permits quoted values; some origins emit them.
        let d = parse(&hdrs(&["max-age=\"45\""]));
        assert_eq!(d.max_age, Some(Duration::from_secs(45)));
    }

    #[test]
    fn unrecognized_directives_ignored() {
        let d = parse(&hdrs(&["public, must-revalidate, s-maxage=99, no-cache"]));
        // None of these flip the fields roxy currently honors.
        assert_eq!(d, CacheDirectives::default());
    }

    #[test]
    fn malformed_max_age_ignored() {
        let d = parse(&hdrs(&["max-age=", "max-age=abc", "max-age=-5"]));
        assert_eq!(d.max_age, None);
    }

    #[test]
    fn extra_whitespace_around_directives_tolerated() {
        let d = parse(&hdrs(&["  no-store  ,  max-age = 7  "]));
        assert!(d.no_store);
        assert_eq!(d.max_age, Some(Duration::from_secs(7)));
    }
}
