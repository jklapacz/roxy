use rusqlite::Connection;
use std::path::Path;

const SCHEMA_VERSION: i64 = 2;

const SCHEMA_V2: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS entries (
    key            BLOB NOT NULL,
    vary_selector  BLOB NOT NULL,
    vary_headers   TEXT NULL,
    content_hash   BLOB NOT NULL,
    status         INTEGER NOT NULL,
    headers_json   TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    ttl_seconds    INTEGER NOT NULL,
    PRIMARY KEY (key, vary_selector)
);

CREATE INDEX IF NOT EXISTS entries_content_hash ON entries(content_hash);
"#;

/// Open the cache index, applying migrations as needed.
///
/// `cache_dir` is used during migration to wipe the `blobs/` subdirectory
/// when the on-disk schema version does not match `SCHEMA_VERSION`. Doing
/// the wipe here keeps it cosited with the schema change so blob orphans
/// can never outlive the entries that reference them.
pub fn open(db_path: &Path, cache_dir: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(db_path)?;
    let on_disk: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if on_disk != SCHEMA_VERSION {
        conn.execute_batch("DROP TABLE IF EXISTS entries")?;
        // Best-effort blob wipe. Failures (e.g. missing dir) are non-fatal —
        // the next call to `ensure_dirs` will recreate the layout.
        let _ = std::fs::remove_dir_all(cache_dir.join("blobs"));
    }
    conn.execute_batch(SCHEMA_V2)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_and_creates_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("idx.sqlite");
        let conn = open(&db, dir.path()).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'entries'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn opens_existing_v1_db_drops_table_and_wipes_blobs() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        let db = cache_dir.join("index.sqlite");

        // Build a v1 DB inline.
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "PRAGMA user_version = 1;
                 CREATE TABLE entries (
                    key BLOB PRIMARY KEY,
                    content_hash BLOB NOT NULL,
                    status INTEGER NOT NULL,
                    headers_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    ttl_seconds INTEGER NOT NULL
                 );
                 INSERT INTO entries
                   VALUES (X'0102', X'aa', 200, '[]', 0, 60);",
            )
            .unwrap();
        }
        // Place a stray blob to confirm the wipe.
        let blobs = cache_dir.join("blobs/aa");
        fs::create_dir_all(&blobs).unwrap();
        fs::write(blobs.join("orphan.bin"), b"x").unwrap();

        // Open with the new code path.
        let conn = open(&db, &cache_dir).unwrap();

        // Schema is now v2 and the table is empty.
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2);
        let count: i64 = conn
            .query_row("SELECT count(*) FROM entries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);

        // The columns we will need next exist.
        let cols: Vec<String> = conn
            .prepare("PRAGMA table_info(entries)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(cols.contains(&"vary_selector".to_string()));
        assert!(cols.contains(&"vary_headers".to_string()));

        // The stray blob directory is gone.
        assert!(!cache_dir.join("blobs").exists());
    }

    #[test]
    fn opens_fresh_db_at_v2() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().to_path_buf();
        let db = cache_dir.join("index.sqlite");
        let conn = open(&db, &cache_dir).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2);
    }
}
