use crate::ca::{Ca, CaError};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

pub struct LeafSigner {
    ca: Ca,
}

impl LeafSigner {
    pub fn new(ca: Ca) -> Self {
        Self { ca }
    }

    pub fn mint(&self, sni: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sni);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(
            sni.to_string().try_into().map_err(CaError::Rcgen)?,
        )];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::hours(24);

        // Reload CA into rcgen-issuable form
        let issuer = rcgen::CertificateParams::from_ca_cert_pem(&self.ca.cert_pem)
            .map_err(CaError::Rcgen)?;
        let issuer_cert = issuer
            .self_signed(self.ca.key_pair.as_ref())
            .map_err(CaError::Rcgen)?;
        let cert = params
            .signed_by(&leaf_key, &issuer_cert, self.ca.key_pair.as_ref())
            .map_err(CaError::Rcgen)?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| CaError::Pem(e.to_string()))?;
        Ok(Arc::new(CertifiedKey::new(vec![cert_der], signing_key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;

    #[test]
    fn mints_leaf_for_sni() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let signer = LeafSigner::new(ca);
        let key = signer.mint("example.com").unwrap();
        assert_eq!(key.cert.len(), 1);
    }

    #[test]
    fn two_mints_produce_distinct_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let signer = LeafSigner::new(ca);
        let a = signer.mint("example.com").unwrap();
        let b = signer.mint("example.com").unwrap();
        // Different serial / key each mint.
        assert_ne!(a.cert[0].as_ref(), b.cert[0].as_ref());
    }
}
