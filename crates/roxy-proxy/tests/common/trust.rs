#![allow(clippy::unwrap_used)]
#![allow(dead_code)]

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct TestCa {
    pub cert_pem: String,
    pub key_pair: KeyPair,
}

impl TestCa {
    pub fn new() -> Self {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key_pair).unwrap();
        Self {
            cert_pem: cert.pem(),
            key_pair,
        }
    }

    pub fn mint(&self, sni: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let leaf_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sni);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(sni.to_string().try_into().unwrap())];
        let issuer_params = CertificateParams::from_ca_cert_pem(&self.cert_pem).unwrap();
        let issuer_cert = issuer_params.self_signed(&self.key_pair).unwrap();
        let leaf = params
            .signed_by(&leaf_key, &issuer_cert, &self.key_pair)
            .unwrap();
        let cert_der = CertificateDer::from(leaf.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        (cert_der, key_der)
    }
}
