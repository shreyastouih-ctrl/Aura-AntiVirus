use std::path::PathBuf;

use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::types::{ScanResult, Verdict};

/// SQLite-backed store for scan history and detection details.
pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database (used by tests).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS scan_results (
                id            TEXT PRIMARY KEY,
                file_path     TEXT NOT NULL,
                file_hash     TEXT NOT NULL,
                file_kind     TEXT NOT NULL,
                verdict       TEXT NOT NULL,
                confidence    REAL NOT NULL,
                size_bytes    INTEGER NOT NULL,
                scanned_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scan_results_hash ON scan_results(file_hash);
            CREATE INDEX IF NOT EXISTS idx_scan_results_verdict ON scan_results(verdict);

            CREATE TABLE IF NOT EXISTS detection_hits (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_result_id TEXT NOT NULL,
                layer          TEXT NOT NULL,
                detection_type TEXT NOT NULL,
                family         TEXT,
                reason         TEXT NOT NULL,
                confidence     REAL NOT NULL,
                evidence       TEXT,
                FOREIGN KEY(scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_hits_result ON detection_hits(scan_result_id);
            "#,
        )?;
        Ok(())
    }

    pub fn save_result(&self, result: &ScanResult) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_results
             (id, file_path, file_hash, file_kind, verdict, confidence, size_bytes, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                result.id.to_string(),
                result.file_path.to_string_lossy(),
                result.file_hash_sha256,
                format!("{:?}", result.file_kind),
                result.verdict.name(),
                result.confidence,
                result.size_bytes as i64,
                result.scanned_at.to_rfc3339(),
            ],
        )?;
        for hit in &result.hits {
            self.conn.execute(
                "INSERT INTO detection_hits
                 (scan_result_id, layer, detection_type, family, reason, confidence, evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    result.id.to_string(),
                    format!("{:?}", hit.layer),
                    format!("{:?}", hit.detection_type),
                    hit.family,
                    hit.reason,
                    hit.confidence,
                    hit.evidence.to_string(),
                ],
            )?;
        }
        Ok(())
    }

    /// Count of stored results matching a verdict.
    pub fn count_by_verdict(&self, verdict: Verdict) -> Result<i64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM scan_results WHERE verdict = ?1",
            params![verdict.name()],
            |row| row.get(0),
        )?;
        Ok(n)
    }

    /// Whether a given file hash was previously recorded as a threat.
    pub fn is_known_bad_hash(&self, sha256: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM scan_results WHERE file_hash = ?1 AND verdict != 'Clean'",
            params![sha256],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// Most recent non-clean detections, newest first.
    pub fn recent_threats(&self, limit: usize) -> Result<Vec<ThreatRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, file_hash, verdict, confidence, scanned_at
             FROM scan_results WHERE verdict != 'Clean'
             ORDER BY scanned_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(ThreatRecord {
                file_path: PathBuf::from(row.get::<_, String>(0)?),
                file_hash: row.get(1)?,
                verdict: row.get(2)?,
                confidence: row.get(3)?,
                scanned_at: row.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Recent scan results regardless of verdict.
    pub fn recent_results(&self, limit: usize) -> Result<Vec<ThreatRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, file_hash, verdict, confidence, scanned_at
             FROM scan_results ORDER BY scanned_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(ThreatRecord {
                file_path: PathBuf::from(row.get::<_, String>(0)?),
                file_hash: row.get(1)?,
                verdict: row.get(2)?,
                confidence: row.get(3)?,
                scanned_at: row.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Default on-disk location of the history database.
    pub fn default_path() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("auraav")
            .join("history.db")
    }
}

/// A lightweight row from the scan history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRecord {
    pub file_path: PathBuf,
    pub file_hash: String,
    pub verdict: String,
    pub confidence: f32,
    pub scanned_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DetectionHit, DetectionLayer, DetectionType};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn stores_and_counts() {
        let db = Db::in_memory().unwrap();
        let result = ScanResult {
            id: Uuid::new_v4(),
            file_path: PathBuf::from("/tmp/x"),
            file_hash_sha256: "abc".into(),
            file_kind: crate::filetype::FileKind::Pe,
            verdict: Verdict::Malicious,
            confidence: 0.9,
            hits: vec![DetectionHit {
                layer: DetectionLayer::Hash,
                detection_type: DetectionType::Known,
                reason: "test".into(),
                family: Some("Fam".into()),
                confidence: 0.9,
                evidence: serde_json::json!({}),
            }],
            size_bytes: 10,
            scanned_at: Utc::now(),
        };
        db.save_result(&result).unwrap();
        assert_eq!(db.count_by_verdict(Verdict::Malicious).unwrap(), 1);
        assert!(db.is_known_bad_hash("abc").unwrap());
    }
}
