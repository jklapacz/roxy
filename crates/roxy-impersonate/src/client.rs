use crate::body::ImpersonateBody;
use crate::custom::CustomProfile;
use crate::error::ImpersonateError;
use crate::profile::Profile;
use bytes::Bytes;
use http::{Request, Response};
use http_body::Body;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Wraps a lazily-built pool of `wreq::Client` instances, one per profile in
/// use. Each request is dispatched on the client matching the requested label.
///
/// wreq configures emulation at client construction, so per-request override
/// requires per-profile clients. We accept this; the pool is small (one entry
/// per active profile name) and `wreq::Client` is internally Arc'd so cloning
/// is cheap.
pub struct ImpersonateClient {
    builtin: HashMap<String, Profile>,
    /// Custom profiles loaded from TOML. On collision with a builtin the
    /// builtin wins, so anything in this map is guaranteed to NOT have a
    /// builtin entry under the same name.
    custom: HashMap<String, wreq::Emulation>,
    clients: Arc<RwLock<HashMap<String, wreq::Client>>>,
    /// Optional certificate store applied to every lazily-built `wreq::Client`.
    ///
    /// Defaults to `None`, meaning wreq uses its own default trust store (the
    /// webpki roots when the `webpki-roots` feature is enabled). When set, the
    /// supplied store fully replaces wreq's default. Constructed via
    /// [`Self::with_custom_and_extra_root_pem`] for the integration-test
    /// scenario where the upstream is signed by a private (test) CA that
    /// is not in webpki-roots.
    cert_store: Option<wreq::tls::CertStore>,
    /// Optional upstream proxy applied to every lazily-built `wreq::Client`.
    /// `None` => wreq dials origins directly.
    proxy: Option<roxy_config::ProxyEndpoint>,
}

impl Default for ImpersonateClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ImpersonateClient {
    pub fn new() -> Self {
        Self::with_custom(Vec::new())
    }

    /// Construct with a (possibly empty) set of custom profiles.
    ///
    /// On name collision with a builtin, the builtin wins and a warning is
    /// logged. Collisions within the custom set itself keep the first one and
    /// log a warning for subsequent duplicates.
    pub fn with_custom(customs: Vec<CustomProfile>) -> Self {
        Self::build(customs, None)
    }

    /// Route every lazily-built `wreq::Client` through `proxy`. `None` leaves
    /// the client dialing origins directly. Chainable on top of any
    /// constructor (`new`, `with_custom`, `with_custom_and_extra_root_pem`).
    pub fn with_proxy(mut self, proxy: Option<roxy_config::ProxyEndpoint>) -> Self {
        self.proxy = proxy;
        self
    }

    /// Like [`Self::with_custom`] but installs an explicit TLS trust store
    /// from the supplied PEM-encoded root certificate(s). The supplied store
    /// REPLACES wreq's default trust (webpki-roots), so callers must include
    /// every CA they need to verify upstream peers.
    ///
    /// Intended primarily for integration tests that need to talk to a fake
    /// origin signed by a private CA — wreq's `webpki-roots` default trust
    /// store does not consult `SSL_CERT_FILE`, so test code must supply the
    /// test CA explicitly. Production callers wanting "webpki + extras"
    /// must concatenate the public root PEMs with their internal root PEM
    /// in `extra_root_pem`.
    ///
    /// Gated behind the `test-utils` Cargo feature (and `cfg(test)` for
    /// internal unit tests) so this footgun is not present in production
    /// binaries. Production callers should never need this constructor.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_custom_and_extra_root_pem(
        customs: Vec<CustomProfile>,
        extra_root_pem: &[u8],
    ) -> Result<Self, ImpersonateError> {
        // Build a cert store containing ONLY the supplied PEM root(s). The
        // resulting store replaces wreq's default webpki trust — that is
        // acceptable for integration tests where the wreq client only talks
        // to a fake origin signed by the supplied CA. Production callers
        // wanting "webpki + extras" must instead pass a PEM stack that
        // includes both the public CAs they care about and their internal
        // root(s).
        let store = wreq::tls::CertStore::builder()
            .add_stack_pem_certs(extra_root_pem)
            .build()
            .map_err(ImpersonateError::Wreq)?;
        Ok(Self::build(customs, Some(store)))
    }

    fn build(customs: Vec<CustomProfile>, cert_store: Option<wreq::tls::CertStore>) -> Self {
        let mut builtin = HashMap::new();
        for p in Profile::all() {
            builtin.insert(p.name().to_string(), *p);
        }
        let mut custom = HashMap::new();
        for c in customs {
            let name = c.spec.name.clone();
            if builtin.contains_key(&name) {
                tracing::warn!(
                    profile = %name,
                    source = ?c.source_path,
                    "custom profile collides with builtin; builtin wins"
                );
                continue;
            }
            if custom.contains_key(&name) {
                tracing::warn!(
                    profile = %name,
                    source = ?c.source_path,
                    "duplicate custom profile name; keeping the first"
                );
                continue;
            }
            custom.insert(name, c.emulation);
        }
        Self {
            builtin,
            custom,
            clients: Arc::new(RwLock::new(HashMap::new())),
            cert_store,
            proxy: None,
        }
    }

    /// Returns true if a profile with the given label is registered (builtin
    /// or custom).
    pub fn has_profile(&self, label: &str) -> bool {
        self.builtin.contains_key(label) || self.custom.contains_key(label)
    }

    /// Sorted list of registered profile names. For diagnostic messages only.
    pub fn profile_names(&self) -> Vec<String> {
        let mut v: Vec<_> = self
            .builtin
            .keys()
            .cloned()
            .chain(self.custom.keys().cloned())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Returns the wreq::Client for the named profile, building it lazily.
    async fn client_for(&self, label: &str) -> Result<wreq::Client, ImpersonateError> {
        // Fast path: already built.
        if let Some(c) = self.clients.read().await.get(label) {
            return Ok(c.clone());
        }
        // Resolve which profile this label refers to before taking the write
        // lock so unknown labels never hold the write guard.
        if !self.has_profile(label) {
            return Err(ImpersonateError::UnknownFingerprint(label.to_string()));
        }
        // Acquire write lock and double-check before building. If another task
        // raced in and built the client between the read-lock drop and the
        // write-lock acquisition, reuse its result instead of constructing a
        // throwaway client.
        let mut w = self.clients.write().await;
        if let Some(c) = w.get(label) {
            return Ok(c.clone());
        }
        // Builtins take precedence on lookup (matching the collision rule),
        // then customs.
        let mut builder = if let Some(p) = self.builtin.get(label).copied() {
            wreq::Client::builder().emulation(p.emulation())
        } else if let Some(emu) = self.custom.get(label) {
            wreq::Client::builder().emulation(emu.clone())
        } else {
            // has_profile said yes; the maps say no. Should be unreachable,
            // but treat it as an unknown label rather than panicking.
            return Err(ImpersonateError::UnknownFingerprint(label.to_string()));
        };
        if let Some(store) = &self.cert_store {
            builder = builder.cert_store(store.clone());
        }
        if let Some(ep) = &self.proxy {
            // wreq's `Proxy` mirrors reqwest's API. Credentials are passed via
            // `basic_auth` rather than embedded in the URL so they never end
            // up in a logged proxy URL string.
            let mut p = wreq::Proxy::all(ep.url_no_auth())?;
            if let Some(a) = &ep.auth {
                p = p.basic_auth(&a.username, &a.password);
            }
            builder = builder.proxy(p);
        }
        let client = builder.build()?;
        w.insert(label.to_string(), client.clone());
        Ok(client)
    }

    /// Send a request through the wreq client for the named profile.
    ///
    /// The supplied request body is collected into bytes before forwarding;
    /// streaming request bodies are not supported in v1 because wreq's body
    /// shape differs from hyper's and the v1 use case (GET-heavy stealth
    /// scraping) does not need it.
    pub async fn send<B>(
        &self,
        label: &str,
        req: Request<B>,
    ) -> Result<Response<ImpersonateBody>, ImpersonateError>
    where
        B: Body<Data = Bytes, Error = std::io::Error> + Send + Unpin + 'static,
    {
        use http_body_util::BodyExt;

        let client = self.client_for(label).await?;
        let (parts, body) = req.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map_err(|e| ImpersonateError::RequestBodyCollect(anyhow::anyhow!("{e}")))?
            .to_bytes();

        let method = parts.method;
        let url = parts.uri.to_string();

        let mut builder = client.request(method, &url);
        for (name, value) in parts.headers.iter() {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
        if !body_bytes.is_empty() {
            builder = builder.body(body_bytes.to_vec());
        }
        let wreq_resp = builder.send().await?;

        let status = wreq_resp.status();
        let headers = wreq_resp.headers().clone();
        let imp_body = ImpersonateBody::from_response(wreq_resp);

        let mut http_resp = Response::new(imp_body);
        *http_resp.status_mut() = status;
        *http_resp.headers_mut() = headers;
        Ok(http_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_profile_label_errors() {
        let c = ImpersonateClient::new();
        match c.client_for("chrome-999").await {
            Err(ImpersonateError::UnknownFingerprint(label)) => {
                assert_eq!(label, "chrome-999")
            }
            Err(other) => panic!("expected UnknownFingerprint, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn builds_client_for_known_profile() {
        let c = ImpersonateClient::new();
        let _ = c.client_for("chrome-137").await.unwrap();
        let _ = c.client_for("chrome-137").await.unwrap();
        assert!(c.clients.read().await.contains_key("chrome-137"));
    }

    #[test]
    fn profile_names_lists_all_builtins() {
        let c = ImpersonateClient::new();
        let names = c.profile_names();
        assert!(names.contains(&"chrome-137".to_string()));
        assert!(names.contains(&"firefox-139".to_string()));
    }

    #[tokio::test]
    async fn collision_skips_custom_keeps_builtin() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("chrome-137.toml");
        std::fs::write(&p, tests_helper::COLLIDING_SPEC).unwrap();
        let customs = crate::CustomProfile::load_dir(dir.path()).unwrap();
        assert_eq!(customs.len(), 1);
        let client = ImpersonateClient::with_custom(customs);
        // Profile name still resolves (the builtin is still registered).
        assert!(client.has_profile("chrome-137"));
        // No new profiles were added on top of the builtins — the colliding
        // custom must have been skipped. We assert via the public surface
        // (profile_names) rather than touching internal fields.
        assert_eq!(
            client.profile_names().len(),
            crate::profile::Profile::all().len()
        );
    }

    #[test]
    fn with_proxy_sets_the_field() {
        let ep = roxy_config::ProxyEndpoint {
            host: "corp-proxy".to_string(),
            port: 8080,
            auth: None,
        };
        let c = ImpersonateClient::new().with_proxy(Some(ep.clone()));
        assert_eq!(c.proxy, Some(ep));
    }

    #[test]
    fn no_proxy_by_default() {
        let c = ImpersonateClient::new();
        assert_eq!(c.proxy, None);
    }
}

#[cfg(test)]
mod tests_helper {
    pub const COLLIDING_SPEC: &str = r#"
name = "chrome-137"

[tls]
alpn = ["h2"]
cipher_suites = ["TLS_AES_128_GCM_SHA256"]
signature_algorithms = ["ecdsa_secp256r1_sha256"]
supported_versions = ["TLS1.3"]
supported_groups = ["X25519"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE"]
header_order = [":method"]
"#;
}
