use crate::leaf::LeafSigner;
use lru::LruCache;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

pub struct SniResolver {
    signer: LeafSigner,
    cache: Mutex<LruCache<String, Arc<CertifiedKey>>>,
}

impl SniResolver {
    pub fn new(signer: LeafSigner, capacity: NonZeroUsize) -> Self {
        Self {
            signer,
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniResolver").finish()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        let sni_owned = sni.to_string();
        {
            let mut cache = self.cache.lock().ok()?;
            if let Some(k) = cache.get(&sni_owned) {
                return Some(k.clone());
            }
        }
        let minted = self.signer.mint(&sni_owned).ok()?;
        let mut cache = self.cache.lock().ok()?;
        cache.put(sni_owned, minted.clone());
        Some(minted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;

    #[test]
    fn resolver_can_be_constructed() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let signer = LeafSigner::new(ca);
        let _ = SniResolver::new(signer, NonZeroUsize::new(10).unwrap());
    }
}
