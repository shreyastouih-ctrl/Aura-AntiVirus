pub mod disasm;
pub mod heuristics;
pub mod similarity;
pub mod structural;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::filetype::{classify_file, FileKind};
use crate::signatures::SignatureDb;
use crate::types::{DetectionHit, DetectionLayer, ScanConfig, ScanResult, Verdict};

use similarity::FuzzyDigest;

/// Only the first N bytes are pulled into memory for content analysis. Hashing
/// always covers the full file via streaming.
const MAX_CONTENT_BYTES: usize = 64 * 1024 * 1024;

const MALICIOUS_THRESHOLD: f32 = 0.80;
const SUSPICIOUS_THRESHOLD: f32 = 0.40;

pub struct Detector {
    db: SignatureDb,
    config: ScanConfig,
}

impl Detector {
    pub fn new(db: SignatureDb, config: ScanConfig) -> Self {
        Self { db, config }
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    pub fn db(&self) -> &SignatureDb {
        &self.db
    }

    /// Scan a file from disk. Returns `None` if it cannot be read.
    pub fn scan_file(&self, path: &Path) -> Option<ScanResult> {
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        let size = meta.len();
        let (sha256, content) = read_and_hash(path).ok()?;
        let kind = classify_file(path, &content);
        Some(self.evaluate(path, size, &sha256, kind, &content))
    }

    /// Scan an in-memory buffer with a known path.
    pub fn scan_bytes(&self, path: &Path, data: &[u8]) -> ScanResult {
        let sha256 = crate::common::sha256_bytes(data);
        let kind = classify_file(path, data);
        self.evaluate(path, data.len() as u64, &sha256, kind, data)
    }

    fn evaluate(
        &self,
        path: &Path,
        size: u64,
        sha256: &str,
        kind: FileKind,
        data: &[u8],
    ) -> ScanResult {
        let sample = &data[..data.len().min(MAX_CONTENT_BYTES)];
        let mut hits: Vec<DetectionHit> = Vec::new();

        // L1: exact hash signatures.
        if let Some(sig) = self.db.lookup_hash(sha256) {
            hits.push(DetectionHit {
                layer: DetectionLayer::Hash,
                detection_type: sig.detection_type,
                reason: format!("known malware signature: {}", sig.name),
                family: non_empty(&sig.family),
                confidence: sig.severity,
                evidence: json!({ "sha256": sha256, "name": sig.name }),
            });
        }

        // L2: pattern rules.
        for (rule, matched) in self.db.match_rules_with_counts(sample) {
            // On real executables, script-oriented rules are noisy (they match
            // embedded strings) and a single loose substring is not evidence.
            if kind.is_executable() {
                if rule.detection_type == crate::types::DetectionType::Script {
                    continue;
                }
                let specific_single = rule.patterns.len() == 1 && rule.patterns[0].len() >= 12;
                if matched < 2 && !specific_single {
                    continue;
                }
            }
            hits.push(DetectionHit {
                layer: DetectionLayer::Yara,
                detection_type: rule.detection_type,
                reason: format!("matched rule '{}'", rule.name),
                family: non_empty(&rule.family),
                confidence: rule.severity,
                evidence: json!({ "rule": rule.name, "patterns_matched": matched }),
            });
        }

        // L3: structural analysis (packing / tampering / stealth).
        if kind.is_executable() {
            hits.extend(structural::analyze(kind, sample));
        }

        // L5/L6: normalized-code similarity (metamorphic families).
        if kind.is_executable() {
            self.code_similarity(kind, sample, &mut hits);
        }

        // L8: fuzzy byte similarity (polymorphic variants).
        self.fuzzy_similarity(sample, &mut hits);

        // L9: static heuristics.
        if self.config.enable_heuristics {
            hits.extend(heuristics::analyze(
                kind,
                sample,
                self.config.heuristic_sensitivity,
            ));
        }

        let (verdict, confidence) = fuse(&hits);
        if verdict == Verdict::Clean {
            hits.clear();
        }

        ScanResult {
            id: Uuid::new_v4(),
            file_path: path.to_path_buf(),
            file_hash_sha256: sha256.to_string(),
            file_kind: kind,
            verdict,
            confidence,
            hits,
            size_bytes: size,
            scanned_at: Utc::now(),
        }
    }

    fn code_similarity(&self, kind: FileKind, data: &[u8], hits: &mut Vec<DetectionHit>) {
        if self.db.code_count() == 0 {
            return;
        }
        let Some(fp) = disasm::fingerprint(kind, data) else {
            return;
        };
        let min_sim = (0.75 * self.config.similarity_sensitivity.multiplier()).min(0.95);
        if let Some((sig, sim)) = self.db.best_code_match(&fp, min_sim) {
            hits.push(DetectionHit {
                layer: DetectionLayer::Cfg,
                detection_type: sig.detection_type,
                reason: format!(
                    "code structure {:.0}% similar to known family '{}'",
                    sim * 100.0,
                    sig.name
                ),
                family: non_empty(&sig.family),
                confidence: (sig.severity * sim).clamp(0.0, 0.75),
                evidence: json!({ "similarity": sim, "name": sig.name }),
            });
        }
    }

    fn fuzzy_similarity(&self, data: &[u8], hits: &mut Vec<DetectionHit>) {
        if self.db.fuzzy_count() == 0 {
            return;
        }
        let digest = FuzzyDigest::compute(data);
        let max_distance = self.config.similarity_sensitivity.max_distance();
        if let Some((sig, distance)) = self.db.best_fuzzy_match(&digest, max_distance) {
            let closeness = 1.0 - (distance as f32 / max_distance.max(1) as f32);
            hits.push(DetectionHit {
                layer: DetectionLayer::Similarity,
                detection_type: sig.detection_type,
                reason: format!("fuzzy match to '{}' (distance {distance})", sig.name),
                family: non_empty(&sig.family),
                confidence: (0.55 * sig.severity * closeness).clamp(0.0, 0.7),
                evidence: json!({ "distance": distance, "name": sig.name }),
            });
        }
    }
}

/// Combine independent confidence scores with a noisy-OR and pick a verdict.
///
/// A `Malicious` verdict requires at least one *definitive* signal — an exact
/// hash match or a strong code/fuzzy-similarity match. Heuristic and rule-only
/// evidence can climb to `Suspicious` but never triggers an automatic removal,
/// which keeps false positives on ordinary software in check.
fn fuse(hits: &[DetectionHit]) -> (Verdict, f32) {
    if hits.is_empty() {
        return (Verdict::Clean, 0.0);
    }
    let mut prod = 1.0f32;
    for h in hits {
        prod *= 1.0 - h.confidence.clamp(0.0, 1.0);
    }
    let mut confidence = (1.0 - prod).clamp(0.0, 1.0);

    let definitive = hits.iter().any(|h| match h.layer {
        DetectionLayer::Hash => h.confidence >= 0.9,
        DetectionLayer::Similarity
        | DetectionLayer::Cfg
        | DetectionLayer::FunctionSim
        | DetectionLayer::InstructionNorm => h.confidence >= 0.55,
        _ => false,
    });

    let verdict = if definitive && confidence >= MALICIOUS_THRESHOLD {
        Verdict::Malicious
    } else if confidence >= SUSPICIOUS_THRESHOLD {
        if !definitive {
            confidence = confidence.min(0.79);
        }
        Verdict::Suspicious
    } else {
        Verdict::Clean
    };
    (verdict, confidence)
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// Stream-hash the whole file while keeping the first [`MAX_CONTENT_BYTES`] in
/// memory for content analysis.
fn read_and_hash(path: &Path) -> std::io::Result<(String, Vec<u8>)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut content = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if content.len() < MAX_CONTENT_BYTES {
            let remaining = MAX_CONTENT_BYTES - content.len();
            let take = remaining.min(n);
            content.extend_from_slice(&buf[..take]);
        }
    }
    Ok((hex::encode(hasher.finalize()), content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_file_scores_no_hits() {
        let db = SignatureDb::new();
        let det = Detector::new(db, ScanConfig::default());
        let res = det.scan_bytes(Path::new("hello.txt"), b"just an ordinary text file\n");
        assert_eq!(res.verdict, Verdict::Clean);
        assert!(res.hits.is_empty());
    }

    #[test]
    fn known_hash_is_malicious() {
        let mut db = SignatureDb::new();
        db.add_hash(crate::signatures::HashSignature {
            sha256: crate::common::sha256_bytes(b"bad"),
            name: "Bad.Thing".to_string(),
            family: "Test".to_string(),
            detection_type: crate::types::DetectionType::Known,
            severity: 0.95,
        });
        let det = Detector::new(db, ScanConfig::default());
        let res = det.scan_bytes(Path::new("bad.bin"), b"bad");
        assert_eq!(res.verdict, Verdict::Malicious);
        assert!(!res.hits.is_empty());
    }
}
