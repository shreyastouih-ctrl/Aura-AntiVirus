use serde::{Deserialize, Serialize};

use crate::detection::disasm::CodeFingerprint;
use crate::detection::similarity::FuzzyDigest;
use crate::types::DetectionType;

/// A known-malware fuzzy (byte-level) fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzySignature {
    pub name: String,
    #[serde(default)]
    pub family: String,
    #[serde(default = "default_type")]
    pub detection_type: DetectionType,
    #[serde(default = "default_severity")]
    pub severity: f32,
    pub digest: FuzzyDigest,
}

/// A known-malware normalized-code fingerprint (metamorphic families).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSignature {
    pub name: String,
    #[serde(default)]
    pub family: String,
    #[serde(default = "default_type")]
    pub detection_type: DetectionType,
    #[serde(default = "default_severity")]
    pub severity: f32,
    pub stream_mins: Vec<u32>,
    pub set_mins: Vec<u32>,
}

impl CodeSignature {
    pub fn from_fingerprint(
        name: impl Into<String>,
        family: impl Into<String>,
        detection_type: DetectionType,
        severity: f32,
        fp: &CodeFingerprint,
    ) -> Self {
        Self {
            name: name.into(),
            family: family.into(),
            detection_type,
            severity,
            stream_mins: fp.mnemonic_stream.mins.clone(),
            set_mins: fp.mnemonic_set.mins.clone(),
        }
    }

    pub fn similarity(&self, fp: &CodeFingerprint) -> f32 {
        let stored_stream = FuzzyDigest {
            mins: self.stream_mins.clone(),
            length: 0,
        };
        let stored_set = FuzzyDigest {
            mins: self.set_mins.clone(),
            length: 0,
        };
        0.4 * stored_stream.similarity(&fp.mnemonic_stream)
            + 0.6 * stored_set.similarity(&fp.mnemonic_set)
    }
}

fn default_type() -> DetectionType {
    DetectionType::Metamorphic
}

fn default_severity() -> f32 {
    0.7
}
