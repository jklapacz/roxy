use std::fmt;

use http::Request;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey(Vec<u8>);

impl CacheKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_parts(
        profile: &str,
        method: &str,
        scheme: &str,
        host: &str,
        path: &str,
        query: Option<&str>,
    ) -> Self {
        let sorted_query = query.map(sort_query).unwrap_or_default();
        let mut buf = Vec::with_capacity(
            profile.len()
                + method.len()
                + scheme.len()
                + host.len()
                + path.len()
                + sorted_query.len()
                + 5,
        );
        buf.extend_from_slice(profile.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(method.to_ascii_uppercase().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(scheme.to_ascii_lowercase().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(host.to_ascii_lowercase().as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(path.as_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(sorted_query.as_bytes());
        Self(buf)
    }

    pub fn from_request<B>(
        req: &Request<B>,
        profile: &str,
        default_scheme: &str,
        default_host: &str,
    ) -> Self {
        let method = req.method().as_str();
        let uri = req.uri();
        let scheme = uri.scheme_str().unwrap_or(default_scheme);
        let host = uri
            .host()
            .or_else(|| {
                req.headers()
                    .get(http::header::HOST)
                    .and_then(|h| h.to_str().ok())
            })
            .unwrap_or(default_host);
        let path = uri.path();
        let query = uri.query();
        Self::from_parts(profile, method, scheme, host, path, query)
    }
}

fn sort_query(q: &str) -> String {
    let mut pairs: Vec<&str> = q.split('&').filter(|s| !s.is_empty()).collect();
    pairs.sort();
    pairs.join("&")
}

impl fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CacheKey({:?})", String::from_utf8_lossy(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_uppercased_scheme_host_lowercased() {
        let a = CacheKey::from_parts("p", "get", "HTTPS", "Example.COM", "/api", None);
        let b = CacheKey::from_parts("p", "GET", "https", "example.com", "/api", None);
        assert_eq!(a, b);
    }

    #[test]
    fn query_params_sorted() {
        let a = CacheKey::from_parts("p", "GET", "https", "a.b", "/p", Some("z=2&a=1"));
        let b = CacheKey::from_parts("p", "GET", "https", "a.b", "/p", Some("a=1&z=2"));
        assert_eq!(a, b);
    }

    #[test]
    fn different_paths_differ() {
        let a = CacheKey::from_parts("p", "GET", "https", "a.b", "/x", None);
        let b = CacheKey::from_parts("p", "GET", "https", "a.b", "/y", None);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_query_treated_as_absent() {
        let a = CacheKey::from_parts("p", "GET", "https", "a.b", "/x", None);
        let b = CacheKey::from_parts("p", "GET", "https", "a.b", "/x", Some(""));
        assert_eq!(a, b);
    }

    #[test]
    fn from_request_picks_authority_from_uri() {
        let r = http::Request::get("https://example.com/api?b=2&a=1")
            .body(())
            .unwrap();
        let k = CacheKey::from_request(&r, "p", "http", "fallback");
        let expected =
            CacheKey::from_parts("p", "GET", "https", "example.com", "/api", Some("a=1&b=2"));
        assert_eq!(k, expected);
    }

    #[test]
    fn different_profiles_differ() {
        let a = CacheKey::from_parts("chrome-137", "GET", "https", "a.b", "/x", None);
        let b = CacheKey::from_parts("firefox-139", "GET", "https", "a.b", "/x", None);
        assert_ne!(a, b);
    }

    #[test]
    fn default_profile_label_is_distinct_from_named() {
        let a = CacheKey::from_parts("_default", "GET", "https", "a.b", "/x", None);
        let b = CacheKey::from_parts("chrome-137", "GET", "https", "a.b", "/x", None);
        assert_ne!(a, b);
    }
}
