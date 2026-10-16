use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::ScanResult;

/// A single quarantined file and its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: Uuid,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub file_hash_sha256: String,
    pub reason: String,
    pub family: Option<String>,
    pub confidence: f32,
    pub size_bytes: u64,
    pub quarantined_at: DateTime<Utc>,
}

/// Manages the quarantine directory and its metadata index.
pub struct QuarantineManager {
    base_dir: PathBuf,
    index_path: PathBuf,
}

impl QuarantineManager {
    /// Open (or create) the default quarantine store.
    pub fn open_default() -> Result<Self> {
        let base = dirs::data_dir()
            .context("cannot determine user data directory")?
            .join("auraav")
            .join("quarantine");
        Self::open(base)
    }

    pub fn open(base_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_dir)?;
        let index_path = base_dir.join("index.jsonl");
        Ok(Self { base_dir, index_path })
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Move a detected file into quarantine and record its metadata.
    pub fn quarantine(&self, result: &ScanResult, reason: &str) -> Result<QuarantineEntry> {
        let id = Uuid::new_v4();
        let file_name = result
            .file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        let dest = self.base_dir.join(format!("{id}_{file_name}"));

        // Move by rename when possible, fall back to copy+remove across devices.
        if fs::rename(&result.file_path, &dest).is_err() {
            fs::copy(&result.file_path, &dest)
                .with_context(|| format!("copying {} into quarantine", result.file_path.display()))?;
            fs::remove_file(&result.file_path).ok();
        }
        // Strip executable bits so the sample cannot be run from quarantine.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&dest) {
                let mut perms = meta.permissions();
                perms.set_mode(0o000);
                let _ = fs::set_permissions(&dest, perms);
            }
        }

        let entry = QuarantineEntry {
            id,
            original_path: result.file_path.clone(),
            quarantine_path: dest,
            file_hash_sha256: result.file_hash_sha256.clone(),
            reason: reason.to_string(),
            family: result.hits.iter().find_map(|h| h.family.clone()),
            confidence: result.confidence,
            size_bytes: result.size_bytes,
            quarantined_at: Utc::now(),
        };
        self.append(&entry)?;
        Ok(entry)
    }

    /// All current quarantine entries.
    pub fn list(&self) -> Result<Vec<QuarantineEntry>> {
        if !self.index_path.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&self.index_path)?;
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<QuarantineEntry>(line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// Restore a quarantined file to its original location.
    pub fn restore(&self, id: Uuid) -> Result<()> {
        let entry = self
            .find(id)?
            .context("quarantine entry not found")?;

        if let Some(parent) = entry.original_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&entry.quarantine_path, &entry.original_path)
            .or_else(|_| fs::copy(&entry.quarantine_path, &entry.original_path).map(|_| ()))
            .with_context(|| format!("restoring {}", entry.original_path.display()))?;

        // Restore normal permissions (best effort).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&entry.original_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o644);
                let _ = fs::set_permissions(&entry.original_path, perms);
            }
        }
        self.remove_index_entry(id)?;
        Ok(())
    }

    /// Permanently delete a quarantined file.
    pub fn delete(&self, id: Uuid) -> Result<()> {
        if let Some(entry) = self.find(id)? {
            let _ = fs::remove_file(&entry.quarantine_path);
        }
        self.remove_index_entry(id)?;
        Ok(())
    }

    pub fn find(&self, id: Uuid) -> Result<Option<QuarantineEntry>> {
        Ok(self.list()?.into_iter().find(|e| e.id == id))
    }

    fn append(&self, entry: &QuarantineEntry) -> Result<()> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.index_path)?;
        writeln!(file, "{}", serde_json::to_string(entry)?)?;
        Ok(())
    }

    fn remove_index_entry(&self, id: Uuid) -> Result<()> {
        let entries: Vec<_> = self.list()?.into_iter().filter(|e| e.id != id).collect();
        let mut out = String::new();
        for e in entries {
            out.push_str(&serde_json::to_string(&e)?);
            out.push('\n');
        }
        fs::write(&self.index_path, out)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Verdict;

    fn sample_result(path: &Path) -> ScanResult {
        ScanResult {
            id: Uuid::new_v4(),
            file_path: path.to_path_buf(),
            file_hash_sha256: "deadbeef".into(),
            file_kind: crate::filetype::FileKind::Other,
            verdict: Verdict::Malicious,
            confidence: 0.9,
            hits: Vec::new(),
            size_bytes: 4,
            scanned_at: Utc::now(),
        }
    }

    #[test]
    fn quarantine_and_restore_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = QuarantineManager::open(tmp.path().join("q")).unwrap();

        let victim = tmp.path().join("evil.bin");
        fs::write(&victim, b"bad!").unwrap();
        let result = sample_result(&victim);

        let entry = mgr.quarantine(&result, "test").unwrap();
        assert!(!victim.exists());
        assert!(entry.quarantine_path.exists());
        assert_eq!(mgr.list().unwrap().len(), 1);

        mgr.restore(entry.id).unwrap();
        assert!(victim.exists());
        assert!(mgr.list().unwrap().is_empty());
    }
}
