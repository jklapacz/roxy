use crate::ca::Ca;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("unsupported platform")]
    Unsupported,

    #[error("command failed: {0}")]
    Command(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("not running as root - run: {0}")]
    NeedsRoot(String),
}

#[derive(Debug)]
pub enum Plan {
    Execute(Vec<String>),
    PrintOnly(Vec<String>),
    AlreadyInstalled,
}

/// SHA-256 over the DER-encoded CA certificate.
pub fn fingerprint_hex(ca: &Ca) -> Result<String, TrustError> {
    let mut cursor = std::io::Cursor::new(ca.cert_pem.as_bytes());
    let mut der_iter = rustls_pemfile::certs(&mut cursor);
    let der = der_iter
        .next()
        .ok_or_else(|| TrustError::Command("CA pem has no certificate".into()))?
        .map_err(|e| TrustError::Command(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(der.as_ref());
    Ok(hex::encode(h.finalize()))
}

pub fn install(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    #[cfg(target_os = "macos")]
    return macos::install(ca, print_only);
    #[cfg(target_os = "linux")]
    return linux::install(ca, print_only);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ca, print_only);
        Err(TrustError::Unsupported)
    }
}

pub fn uninstall(ca: &Ca, print_only: bool) -> Result<Plan, TrustError> {
    #[cfg(target_os = "macos")]
    return macos::uninstall(ca, print_only);
    #[cfg(target_os = "linux")]
    return linux::uninstall(ca, print_only);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ca, print_only);
        Err(TrustError::Unsupported)
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let fp = fingerprint_hex(&ca).unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
