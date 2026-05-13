//! UpstreamRouter dispatches to the rustls upstream client or the wreq-based
//! impersonate client based on the resolved profile label. Header parsing and
//! label resolution live in the handler (the caller) — the router only
//! switches on the label string.

use crate::upstream::{UpstreamBody, UpstreamClient, UpstreamError};
use crate::ClientBody;
use http::{Request, Response};
use roxy_impersonate::{ImpersonateClient, DEFAULT_LABEL};

pub struct UpstreamRouter {
    rustls: UpstreamClient,
    impersonate: Option<ImpersonateClient>,
}

impl UpstreamRouter {
    pub fn new(rustls: UpstreamClient, impersonate: Option<ImpersonateClient>) -> Self {
        Self {
            rustls,
            impersonate,
        }
    }

    /// Routes by label:
    ///   - `_default` => rustls path
    ///   - any other label => impersonate path; if impersonate is unconfigured
    ///     or the label is unknown, returns `UnknownFingerprint`.
    pub async fn send(
        &self,
        label: &str,
        req: Request<ClientBody>,
    ) -> Result<Response<UpstreamBody>, UpstreamError> {
        if label == DEFAULT_LABEL {
            return self.rustls.send(req).await;
        }
        let imp = self
            .impersonate
            .as_ref()
            .ok_or_else(|| UpstreamError::UnknownFingerprint(label.to_string()))?;
        if !imp.has_profile(label) {
            return Err(UpstreamError::UnknownFingerprint(label.to_string()));
        }
        let resp = imp.send(label, req).await?;
        let (parts, body) = resp.into_parts();
        Ok(Response::from_parts(parts, UpstreamBody::impersonate(body)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};

    fn empty_body_req() -> Request<ClientBody> {
        let body: ClientBody = Empty::<Bytes>::new().map_err(|n| match n {}).boxed();
        Request::get("http://127.0.0.1:1/").body(body).unwrap()
    }

    #[tokio::test]
    async fn unknown_label_with_no_impersonate_errors() {
        let rustls = UpstreamClient::new().unwrap();
        let router = UpstreamRouter::new(rustls, None);
        let result = router.send("chrome-137", empty_body_req()).await;
        match result {
            Ok(_) => panic!("expected error"),
            Err(UpstreamError::UnknownFingerprint(s)) => assert_eq!(s, "chrome-137"),
            Err(other) => panic!("expected UnknownFingerprint, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_label_with_impersonate_errors() {
        let rustls = UpstreamClient::new().unwrap();
        let router = UpstreamRouter::new(rustls, Some(ImpersonateClient::new()));
        let result = router.send("chrome-999", empty_body_req()).await;
        match result {
            Ok(_) => panic!("expected error"),
            Err(UpstreamError::UnknownFingerprint(s)) => assert_eq!(s, "chrome-999"),
            Err(other) => panic!("expected UnknownFingerprint, got {other:?}"),
        }
    }
}
