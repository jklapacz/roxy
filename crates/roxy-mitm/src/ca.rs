use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("pem: {0}")]
    Pem(String),
}

#[derive(Clone)]
pub struct Ca {
    pub cert_pem: String,
    pub key_pair: Arc<KeyPair>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl Ca {
    pub fn load_or_create(dir: &Path) -> Result<Self, CaError> {
        std::fs::create_dir_all(dir)?;
        let cert_path = dir.join("roxy-ca.crt");
        let key_path = dir.join("roxy-ca.key");
        if cert_path.exists() && key_path.exists() {
            Self::load(&cert_path, &key_path)
        } else {
            Self::create(&cert_path, &key_path)
        }
    }

    fn create(cert_path: &Path, key_path: &Path) -> Result<Self, CaError> {
        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Roxy Local CA");
        dn.push(DnType::OrganizationName, "Roxy");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let not_before = time::OffsetDateTime::now_utc();
        params.not_before = not_before;
        params.not_after = not_before + time::Duration::days(3650);
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        std::fs::write(cert_path, &cert_pem)?;
        std::fs::write(key_path, &key_pem)?;
        Ok(Self {
            cert_pem,
            key_pair: Arc::new(key_pair),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
        })
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self, CaError> {
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        let key_pair = KeyPair::from_pem(&key_pem).map_err(CaError::Rcgen)?;
        Ok(Self {
            cert_pem,
            key_pair: Arc::new(key_pair),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_run_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        assert!(ca.cert_path.exists());
        assert!(ca.key_path.exists());
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn second_call_loads_existing() {
        let dir = tempfile::tempdir().unwrap();
        let a = Ca::load_or_create(dir.path()).unwrap();
        let b = Ca::load_or_create(dir.path()).unwrap();
        assert_eq!(a.cert_pem, b.cert_pem);
    }
}
