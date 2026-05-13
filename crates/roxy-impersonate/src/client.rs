use crate::body::ImpersonateBody;
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
    // Custom profiles are added in Task 5.
    clients: Arc<RwLock<HashMap<String, wreq::Client>>>,
}

impl Default for ImpersonateClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ImpersonateClient {
    pub fn new() -> Self {
        let mut builtin = HashMap::new();
        for p in Profile::all() {
            builtin.insert(p.name().to_string(), *p);
        }
        Self {
            builtin,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns true if a profile with the given label is registered.
    pub fn has_profile(&self, label: &str) -> bool {
        self.builtin.contains_key(label)
    }

    /// Sorted list of registered profile names. For diagnostic messages only.
    pub fn profile_names(&self) -> Vec<String> {
        let mut v: Vec<_> = self.builtin.keys().cloned().collect();
        v.sort();
        v
    }

    /// Returns the wreq::Client for the named profile, building it lazily.
    async fn client_for(&self, label: &str) -> Result<wreq::Client, ImpersonateError> {
        if let Some(c) = self.clients.read().await.get(label) {
            return Ok(c.clone());
        }
        let profile = self
            .builtin
            .get(label)
            .copied()
            .ok_or_else(|| ImpersonateError::UnknownFingerprint(label.to_string()))?;
        let client = wreq::Client::builder()
            .emulation(profile.emulation())
            .build()?;
        self.clients
            .write()
            .await
            .insert(label.to_string(), client.clone());
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
            .map_err(|e| ImpersonateError::CustomLoad {
                path: std::path::PathBuf::from("<request body>"),
                source: anyhow::anyhow!("collect request body: {e}"),
            })?
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
}
