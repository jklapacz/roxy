#![allow(dead_code)] // wired up in Tasks 11-13

use rusqlite::Connection;
use std::path::Path;

pub fn open(db_path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(SCHEMA_V1)?;
    Ok(conn)
}

const SCHEMA_V1: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS entries (
    key          BLOB PRIMARY KEY,
    content_hash BLOB NOT NULL,
    status       INTEGER NOT NULL,
    headers_json TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    ttl_seconds  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS entries_content_hash ON entries(content_hash);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_and_creates_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("idx.sqlite");
        let conn = open(&db).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'entries'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }
}
