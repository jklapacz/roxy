//! Upstream proxy endpoint types and parsing. v1 supports a single HTTP
//! CONNECT proxy; `ProxyEndpoint` is the unit a future rotating pool would
//! hold many of.

use crate::ConfigError;

/// Basic-auth credentials for an upstream proxy, parsed from the userinfo
/// component of the proxy URL (`http://user:pass@host:port`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// A single resolved upstream proxy. v1 config yields zero or one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
}

impl ProxyEndpoint {
    /// Scheme-qualified URL WITHOUT userinfo. Credentials are carried
    /// separately (see `auth`) so they never end up in a logged URL string.
    pub fn url_no_auth(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

/// Parse a proxy URL of the form `http://[user:pass@]host:port`.
///
/// v1 accepts only the `http` scheme and requires a port (HTTP's default 80 is
/// also accepted when present in the URL). A missing host, missing port,
/// non-`http` scheme, or unparseable URL is a `ConfigError::Proxy` so
/// misconfiguration fails fast at startup.
pub fn parse_proxy(raw: &str) -> Result<ProxyEndpoint, ConfigError> {
    let u = url::Url::parse(raw)
        .map_err(|e| ConfigError::Proxy(format!("invalid proxy URL {raw:?}: {e}")))?;
    if u.scheme() != "http" {
        return Err(ConfigError::Proxy(format!(
            "proxy scheme must be \"http\", got {:?} in {raw:?}",
            u.scheme()
        )));
    }
    let host = u
        .host_str()
        .ok_or_else(|| ConfigError::Proxy(format!("proxy URL {raw:?} has no host")))?
        .to_string();
    let port = u
        .port_or_known_default()
        .ok_or_else(|| ConfigError::Proxy(format!("proxy URL {raw:?} has no port")))?;
    if u.path() != "" && u.path() != "/" {
        return Err(ConfigError::Proxy(format!(
            "proxy URL {raw:?} must not include a path; expected http://[user:pass@]host:port"
        )));
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err(ConfigError::Proxy(format!(
            "proxy URL {raw:?} must not include a query or fragment"
        )));
    }
    let auth = if u.username().is_empty() {
        None
    } else {
        Some(ProxyAuth {
            username: u.username().to_string(),
            password: u.password().unwrap_or("").to_string(),
        })
    };
    Ok(ProxyEndpoint { host, port, auth })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_and_port() {
        let ep = parse_proxy("http://corp-proxy:8080").unwrap();
        assert_eq!(ep.host, "corp-proxy");
        assert_eq!(ep.port, 8080);
        assert_eq!(ep.auth, None);
    }

    #[test]
    fn parses_userinfo_into_auth() {
        let ep = parse_proxy("http://alice:s3cret@corp-proxy:8080").unwrap();
        assert_eq!(ep.host, "corp-proxy");
        assert_eq!(ep.port, 8080);
        assert_eq!(
            ep.auth,
            Some(ProxyAuth {
                username: "alice".to_string(),
                password: "s3cret".to_string(),
            })
        );
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err = parse_proxy("socks5://corp-proxy:1080").unwrap_err();
        assert!(matches!(err, ConfigError::Proxy(_)), "got: {err:?}");
    }

    #[test]
    fn accepts_default_http_port_when_missing() {
        let ep = parse_proxy("http://corp-proxy").unwrap();
        assert_eq!(ep.host, "corp-proxy");
        assert_eq!(ep.port, 80);
    }

    #[test]
    fn rejects_garbage() {
        let err = parse_proxy("not a url").unwrap_err();
        assert!(matches!(err, ConfigError::Proxy(_)), "got: {err:?}");
    }

    #[test]
    fn url_no_auth_omits_credentials() {
        let ep = parse_proxy("http://alice:s3cret@corp-proxy:8080").unwrap();
        assert_eq!(ep.url_no_auth(), "http://corp-proxy:8080");
    }

    #[test]
    fn accepts_explicit_default_port() {
        let ep = parse_proxy("http://corp-proxy:80").unwrap();
        assert_eq!(ep.host, "corp-proxy");
        assert_eq!(ep.port, 80);
    }

    #[test]
    fn brackets_ipv6_host() {
        let ep = parse_proxy("http://[::1]:8080").unwrap();
        assert_eq!(ep.host, "[::1]");
        assert_eq!(ep.port, 8080);
        assert_eq!(ep.url_no_auth(), "http://[::1]:8080");
    }

    #[test]
    fn rejects_trailing_path() {
        let err = parse_proxy("http://corp-proxy:8080/some/path").unwrap_err();
        assert!(matches!(err, ConfigError::Proxy(_)), "got: {err:?}");
    }

    #[test]
    fn rejects_trailing_query() {
        let err = parse_proxy("http://corp-proxy:8080?x=1").unwrap_err();
        assert!(matches!(err, ConfigError::Proxy(_)), "got: {err:?}");
    }
}
