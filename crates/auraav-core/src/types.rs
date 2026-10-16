use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::filetype::FileKind;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DetectionLayer {
    Hash,
    Yara,
    Structural,
    Polymorphic,
    InstructionNorm,
    Cfg,
    FunctionSim,
    Similarity,
    Heuristic,
    Behavioral,
}

impl DetectionLayer {
    pub fn name(self) -> &'static str {
        match self {
            DetectionLayer::Hash => "Signature (hash)",
            DetectionLayer::Yara => "Pattern rule",
            DetectionLayer::Structural => "Structural",
            DetectionLayer::Polymorphic => "Polymorphic unpack",
            DetectionLayer::InstructionNorm => "Instruction normalization",
            DetectionLayer::Cfg => "Control-flow similarity",
            DetectionLayer::FunctionSim => "Function similarity",
            DetectionLayer::Similarity => "Fuzzy similarity",
            DetectionLayer::Heuristic => "Heuristic",
            DetectionLayer::Behavioral => "Behavioral",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DetectionType {
    Known,
    Polymorphic,
    Metamorphic,
    FileInfector,
    Trojan,
    Worm,
    Dropper,
    Downloader,
    Ransomware,
    Backdoor,
    Rootkit,
    Script,
    Packed,
    Suspicious,
    Other,
}

impl DetectionType {
    pub fn name(self) -> &'static str {
        match self {
            DetectionType::Known => "Known malware",
            DetectionType::Polymorphic => "Polymorphic",
            DetectionType::Metamorphic => "Metamorphic",
            DetectionType::FileInfector => "File infector",
            DetectionType::Trojan => "Trojan",
            DetectionType::Worm => "Worm",
            DetectionType::Dropper => "Dropper",
            DetectionType::Downloader => "Downloader",
            DetectionType::Ransomware => "Ransomware",
            DetectionType::Backdoor => "Backdoor",
            DetectionType::Rootkit => "Rootkit",
            DetectionType::Script => "Script threat",
            DetectionType::Packed => "Packed/obfuscated",
            DetectionType::Suspicious => "Suspicious",
            DetectionType::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionHit {
    pub layer: DetectionLayer,
    pub detection_type: DetectionType,
    pub reason: String,
    #[serde(default)]
    pub family: Option<String>,
    pub confidence: f32, // 0-1
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Clean => "Clean",
            Verdict::Suspicious => "Suspicious",
            Verdict::Malicious => "Malicious",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub file_path: PathBuf,
    pub file_hash_sha256: String,
    pub file_kind: FileKind,
    pub verdict: Verdict,
    pub confidence: f32,
    pub hits: Vec<DetectionHit>,
    pub size_bytes: u64,
    pub scanned_at: DateTime<Utc>,
}

impl ScanResult {
    pub fn is_threat(&self) -> bool {
        !matches!(self.verdict, Verdict::Clean)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub include_hidden: bool,
    pub exclude_patterns: Vec<String>,
    pub max_file_size_mb: u64,
    pub enable_heuristics: bool,
    pub heuristic_sensitivity: HeuristicSensitivity,
    pub similarity_sensitivity: SimilaritySensitivity,
    pub enable_behavioral: bool,
    pub real_time: bool,
    pub scan_external_drives: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HeuristicSensitivity {
    Off,
    Low,
    Medium,
    High,
}

impl Default for HeuristicSensitivity {
    fn default() -> Self {
        HeuristicSensitivity::Low
    }
}

impl HeuristicSensitivity {
    pub fn multiplier(self) -> f32 {
        match self {
            HeuristicSensitivity::Off => 0.0,
            HeuristicSensitivity::Low => 0.7,
            HeuristicSensitivity::Medium => 1.0,
            HeuristicSensitivity::High => 1.25,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SimilaritySensitivity {
    Strict,
    Balanced,
    Lenient,
}

impl Default for SimilaritySensitivity {
    fn default() -> Self {
        SimilaritySensitivity::Balanced
    }
}

impl SimilaritySensitivity {
    pub fn max_distance(self) -> u32 {
        match self {
            SimilaritySensitivity::Strict => 40,
            SimilaritySensitivity::Balanced => 70,
            SimilaritySensitivity::Lenient => 100,
        }
    }

    pub fn multiplier(self) -> f32 {
        match self {
            SimilaritySensitivity::Strict => 0.8,
            SimilaritySensitivity::Balanced => 1.0,
            SimilaritySensitivity::Lenient => 1.2,
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            include_hidden: false,
            exclude_patterns: vec![
                "**/.git/**".to_string(),
                "**/node_modules/**".to_string(),
                "**/target/**".to_string(),
                "**/__pycache__/**".to_string(),
                "**/.cache/**".to_string(),
            ],
            max_file_size_mb: 512,
            enable_heuristics: true,
            heuristic_sensitivity: HeuristicSensitivity::Low,
            similarity_sensitivity: SimilaritySensitivity::Balanced,
            enable_behavioral: false,
            real_time: false,
            scan_external_drives: true,
        }
    }
}
