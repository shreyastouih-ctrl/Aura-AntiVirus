use crate::filetype::{FileKind, ScriptKind};
use crate::signatures::contains_bytes;
use crate::types::{DetectionHit, DetectionLayer, DetectionType, HeuristicSensitivity};
use serde_json::json;

use super::structural::entropy;

const MAX_SCAN: usize = 4 * 1024 * 1024;

/// Run static heuristics appropriate for the file kind.
///
/// Entropy-based packing hints are only meaningful for executables/unknown
/// binaries; plain text/documents are never flagged on entropy alone. This
/// keeps the false-positive rate low.
pub fn analyze(kind: FileKind, data: &[u8], sensitivity: HeuristicSensitivity) -> Vec<DetectionHit> {
    if sensitivity == HeuristicSensitivity::Off {
        return Vec::new();
    }
    let m = sensitivity.multiplier();
    let sample = &data[..data.len().min(MAX_SCAN)];
    let mut hits = Vec::new();

    match kind {
        FileKind::Pe | FileKind::Elf | FileKind::MachO | FileKind::Binary => {
            analyze_binary(kind, sample, m, &mut hits);
        }
        FileKind::Script(sc) => analyze_script(sc, sample, m, &mut hits),
        _ => {}
    }

    hits.retain(|h| h.confidence >= 0.1);
    hits
}

fn analyze_binary(kind: FileKind, sample: &[u8], m: f32, hits: &mut Vec<DetectionHit>) {
    // Whole-file entropy is only a meaningful packing hint for unknown blobs;
    // recognized executables are analysed per-section instead (see structural).
    if kind == FileKind::Binary {
        let ent = entropy(sample);
        if sample.len() >= 4096 && ent > 7.6 {
            hits.push(det(
                DetectionLayer::Heuristic,
                DetectionType::Packed,
                format!("very high overall entropy ({ent:.2}/8.00) — possible packing/encryption"),
                (0.33 * m).min(0.6),
                json!({ "entropy": ent }),
            ));
        }
    }

    // A *valid* PE header embedded beyond offset 0 is a real dropper /
    // self-extractor hint (a bare "MZ" pair is far too common to be useful).
    if sample.len() > 0x200 && !starts_with_pe(sample) && has_embedded_pe(sample) {
        hits.push(det(
            DetectionLayer::Heuristic,
            DetectionType::Dropper,
            "embedded PE executable (valid MZ/PE header) found inside file",
            (0.45 * m).min(0.7),
            json!({ "embedded_pe": true }),
        ));
    }

    if contains_bytes(sample, b"UPX0") && contains_bytes(sample, b"UPX1") {
        hits.push(det(
            DetectionLayer::Heuristic,
            DetectionType::Packed,
            "UPX packer markers present",
            (0.35 * m).min(0.7),
            json!({}),
        ));
    }
}

fn analyze_script(sc: ScriptKind, sample: &[u8], m: f32, hits: &mut Vec<DetectionHit>) {
    if let Some(len) = find_long_base64(sample) {
        hits.push(det(
            DetectionLayer::Heuristic,
            DetectionType::Packed,
            format!("large base64 blob ({len} chars) — likely embedded/staged payload"),
            (0.30 * m).min(0.55),
            json!({ "base64_length": len }),
        ));
    }

    let tokens = script_tokens(sc);
    let found = scan_tokens(sample, tokens);
    match found.len() {
        0 => {}
        1 => hits.push(det(
            DetectionLayer::Heuristic,
            DetectionType::Script,
            format!("suspicious {} construct: {}", sc.name(), found[0]),
            (0.20 * m).min(0.4),
            json!({ "indicator": found[0] }),
        )),
        n => hits.push(det(
            DetectionLayer::Heuristic,
            DetectionType::Script,
            format!("{n} dynamic-execution/obfuscation indicators: {}", found.join(", ")),
            (0.40 * m).min(0.7),
            json!({ "indicators": found }),
        )),
    }

    if hex_escape_density(sample) {
        hits.push(det(
            DetectionLayer::Heuristic,
            DetectionType::Packed,
            "high density of hex/unicode escapes — possible obfuscation",
            (0.25 * m).min(0.5),
            json!({}),
        ));
    }
}

fn script_tokens(sc: ScriptKind) -> &'static [&'static str] {
    match sc {
        ScriptKind::PowerShell => &[
            "iex",
            "invoke-expression",
            "-encodedcommand",
            "frombase64string",
            "downloadstring",
            "downloadfile",
            "invoke-webrequest",
            "bypass",
        ],
        ScriptKind::Python => &[
            "exec(",
            "eval(",
            "os.system",
            "subprocess",
            "__import__",
            "b64decode",
            "marshal.loads",
            "pickle.loads",
        ],
        ScriptKind::JavaScript | ScriptKind::TypeScript => &[
            "eval(",
            "function(",
            "child_process",
            "execsync",
            "atob(",
            "require('http",
            "require(\"http",
        ],
        ScriptKind::Shell => &[
            "eval ",
            "base64 -d",
            "base64 --decode",
            "curl ",
            "wget ",
            "nc -e",
            "/dev/tcp",
            "chmod +x",
        ],
        ScriptKind::Batch => &["certutil", "powershell", "bitsadmin", "regsvr32"],
        ScriptKind::Vbs => &[
            "createobject",
            "wscript.shell",
            "xmlhttp",
            "shell.application",
            "adodb.stream",
        ],
        _ => &[],
    }
}

fn scan_tokens(sample: &[u8], tokens: &[&str]) -> Vec<String> {
    let text = String::from_utf8_lossy(sample).to_lowercase();
    tokens
        .iter()
        .filter(|t| text.contains(&t.to_lowercase()))
        .map(|t| (*t).to_string())
        .collect()
}

fn find_long_base64(data: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(data);
    let (mut best, mut run) = (0usize, 0usize);
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    (best >= 200).then_some(best)
}

fn hex_escape_density(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(64 * 1024)];
    let mut escapes = 0usize;
    let mut i = 0;
    while i + 3 < sample.len() {
        if sample[i] == b'\\'
            && (sample[i + 1] == b'x' || sample[i + 1] == b'u' || sample[i + 1] == b'u')
            && sample[i + 2].is_ascii_hexdigit()
            && sample[i + 3].is_ascii_hexdigit()
        {
            escapes += 1;
            i += 4;
        } else {
            i += 1;
        }
    }
    escapes > 40
}

fn starts_with_pe(data: &[u8]) -> bool {
    data.len() >= 2 && &data[..2] == b"MZ"
}

fn read_u32_le(data: &[u8], at: usize) -> Option<u32> {
    if at + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        data[at],
        data[at + 1],
        data[at + 2],
        data[at + 3],
    ]))
}

/// True if `data` contains an "MZ" whose `e_lfanew` points at a real PE\0\0
/// signature — i.e. an actually-embeddable executable, not a bare "MZ" pair.
fn has_embedded_pe(data: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 2 <= data.len() {
        if i != 0 && &data[i..i + 2] == b"MZ" {
            if let Some(e_lfanew) = read_u32_le(data, i + 0x3c) {
                let sig = i + e_lfanew as usize;
                if (e_lfanew as usize) < data.len() && sig + 4 <= data.len() {
                    if &data[sig..sig + 4] == b"PE\0\0" {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

fn det(
    layer: DetectionLayer,
    detection_type: DetectionType,
    reason: impl Into<String>,
    confidence: f32,
    evidence: serde_json::Value,
) -> DetectionHit {
    DetectionHit {
        layer,
        detection_type,
        reason: reason.into(),
        family: None,
        confidence,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_not_flagged() {
        let data = b"hello world, this is an ordinary sentence repeated a few times";
        let hits = analyze(FileKind::Text, data, HeuristicSensitivity::High);
        assert!(hits.is_empty());
    }

    #[test]
    fn powershell_obfuscation_flagged() {
        let data = b"powershell -EncodedCommand ZQBjAGgAbwAgAGgAaQA= -bypass IEX(New-Object DownloadString)";
        let hits = analyze(FileKind::Script(ScriptKind::PowerShell), data, HeuristicSensitivity::Medium);
        assert!(!hits.is_empty());
    }

    #[test]
    fn long_base64_flagged() {
        let blob = "A".repeat(300);
        let data = format!("payload = \"{blob}\"");
        let hits = analyze(FileKind::Script(ScriptKind::Python), data.as_bytes(), HeuristicSensitivity::Medium);
        assert!(hits.iter().any(|h| h.detection_type == DetectionType::Packed));
    }
}
