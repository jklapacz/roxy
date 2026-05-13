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
    pub(crate) custom: HashMap<String, wreq::Emulation>,
    clients: Arc<RwLock<HashMap<String, wreq::Client>>>,
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
                    "custom profile collides with builtin; builtin wins"
                );
                continue;
            }
            if custom.contains_key(&name) {
                tracing::warn!(
                    profile = %name,
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
        let client = if let Some(p) = self.builtin.get(label).copied() {
            wreq::Client::builder().emulation(p.emulation()).build()?
        } else if let Some(emu) = self.custom.get(label) {
            wreq::Client::builder().emulation(emu.clone()).build()?
        } else {
            // has_profile said yes; the maps say no. Should be unreachable,
            // but treat it as an unknown label rather than panicking.
            return Err(ImpersonateError::UnknownFingerprint(label.to_string()));
        };
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
    async fn collision_logs_warning_builtin_wins() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("chrome-137.toml");
        std::fs::write(&p, tests_helper::COLLIDING_SPEC).unwrap();
        let customs = crate::CustomProfile::load_dir(dir.path()).unwrap();
        let client = ImpersonateClient::with_custom(customs);
        assert!(client.has_profile("chrome-137"));
        // Builtin wins: custom map does NOT contain chrome-137.
        assert!(!client.custom.contains_key("chrome-137"));
    }
}

#[cfg(test)]
mod tests_helper {
    pub const COLLIDING_SPEC: &str = r#"
name = "chrome-137"

[tls]
alpn = ["h2"]
cipher_suites = ["TLS_AES_128_GCM_SHA256"]
extensions = ["server_name"]
supported_versions = ["TLS1.3"]
signature_algorithms = ["ecdsa_secp256r1_sha256"]

[http2]
header_table_size = 65536
enable_push = false
initial_window_size = 6291456
max_frame_size = 16384
max_header_list_size = 262144
settings_order = ["HEADER_TABLE_SIZE"]
header_order = [":method"]
"#;
}
