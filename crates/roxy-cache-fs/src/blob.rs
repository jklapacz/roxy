#![allow(dead_code)]

use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Path for a blob given its sha256 hex.
pub fn blob_path(cache_dir: &Path, hex: &str) -> PathBuf {
    let prefix = &hex[..2];
    cache_dir
        .join("blobs")
        .join(prefix)
        .join(format!("{hex}.bin"))
}

pub fn tmp_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("tmp").join(Uuid::new_v4().to_string())
}

pub fn ensure_dirs(cache_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(cache_dir.join("tmp"))?;
    std::fs::create_dir_all(cache_dir.join("blobs"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn blob_path_uses_prefix_dir() {
        let p = blob_path(&PathBuf::from("/c"), "abcdef0123456789");
        assert_eq!(p, PathBuf::from("/c/blobs/ab/abcdef0123456789.bin"));
    }

    #[test]
    fn ensure_dirs_creates_blobs_and_tmp() {
        let d = tempfile::tempdir().unwrap();
        ensure_dirs(d.path()).unwrap();
        assert!(d.path().join("blobs").is_dir());
        assert!(d.path().join("tmp").is_dir());
    }
}
