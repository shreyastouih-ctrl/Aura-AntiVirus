use crate::filetype::FileKind;
use crate::types::{DetectionHit, DetectionLayer, DetectionType};
use serde_json::json;

/// Shannon entropy of a byte slice (bits per byte, 0..=8).
pub fn entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut e = 0f64;
    for &c in freq.iter() {
        if c > 0 {
            let p = c as f64 / len;
            e -= p * p.log2();
        }
    }
    e as f32
}

/// Analyze a native executable (PE/ELF/Mach-O) for packing/tampering/stealth
/// characteristics. Confidence values are deliberately modest so a single
/// structural oddity never produces a Malicious verdict on its own.
pub fn analyze(kind: FileKind, data: &[u8]) -> Vec<DetectionHit> {
    match kind {
        FileKind::Pe => analyze_pe(data),
        FileKind::Elf => analyze_elf(data),
        FileKind::MachO => analyze_macho(data),
        _ => Vec::new(),
    }
}

fn analyze_pe(data: &[u8]) -> Vec<DetectionHit> {
    let mut hits = Vec::new();
    let Ok(pe) = goblin::pe::PE::parse(data) else {
        return hits;
    };

    let mut high_entropy_code = 0usize;
    let mut wx_sections = Vec::new();
    let mut suspicious_names = Vec::new();

    for section in &pe.sections {
        let name = section.name().unwrap_or("").trim_end_matches('\0').to_string();
        let start = section.pointer_to_raw_data as usize;
        let end = (start + section.size_of_raw_data as usize).min(data.len());
        let body = if start < end { &data[start..end] } else { &[][..] };

        let ent = entropy(body);
        let is_code = section.characteristics & 0x0000_0020 != 0;
        let exec = section.characteristics & 0x2000_0000 != 0;
        let write = section.characteristics & 0x8000_0000 != 0;

        if (is_code || exec) && ent > 7.2 && body.len() > 1024 {
            high_entropy_code += 1;
        }
        if exec && write {
            wx_sections.push(name.clone());
        }
        if is_suspicious_section_name(&name) {
            suspicious_names.push(name);
        }
    }

    push_section_hits(&mut hits, high_entropy_code, wx_sections, suspicious_names);
    if pe.imports.is_empty() {
        hits.push(DetectionHit {
            layer: DetectionLayer::Structural,
            detection_type: DetectionType::Suspicious,
            reason: "PE with no imports (common in packed droppers)".to_string(),
            family: None,
            confidence: 0.25,
            evidence: json!({ "imports": 0 }),
        });
    }
    hits
}

/// Shared section-based structural hits for PE/ELF.
fn push_section_hits(
    hits: &mut Vec<DetectionHit>,
    high_entropy_code: usize,
    wx_sections: Vec<String>,
    suspicious_names: Vec<String>,
) {
    if high_entropy_code > 0 {
        hits.push(DetectionHit {
            layer: DetectionLayer::Structural,
            detection_type: DetectionType::Packed,
            reason: format!(
                "{high_entropy_code} executable section(s) with very high entropy (likely packed/encrypted)"
            ),
            family: None,
            confidence: 0.35,
            evidence: json!({ "high_entropy_code_sections": high_entropy_code }),
        });
    }
    if !wx_sections.is_empty() {
        hits.push(DetectionHit {
            layer: DetectionLayer::Structural,
            detection_type: DetectionType::Suspicious,
            reason: format!("writable+executable section(s): {}", wx_sections.join(", ")),
            family: None,
            confidence: 0.3,
            evidence: json!({ "wx_sections": wx_sections }),
        });
    }
    if !suspicious_names.is_empty() {
        hits.push(DetectionHit {
            layer: DetectionLayer::Structural,
            detection_type: DetectionType::Suspicious,
            reason: format!("unusual section name(s): {}", suspicious_names.join(", ")),
            family: None,
            confidence: 0.2,
            evidence: json!({ "sections": suspicious_names }),
        });
    }
}

fn analyze_elf(data: &[u8]) -> Vec<DetectionHit> {
    let mut hits = Vec::new();
    let Ok(elf) = goblin::elf::Elf::parse(data) else {
        return hits;
    };

    let mut high_entropy_code = 0usize;
    let mut wx_sections = Vec::new();
    let mut suspicious_names = Vec::new();

    for section in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let start = section.sh_offset as usize;
        let end = (start + section.sh_size as usize).min(data.len());
        let body = if start < end { &data[start..end] } else { &[][..] };

        let exec = section.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0;
        let write = section.sh_flags & u64::from(goblin::elf::section_header::SHF_WRITE) != 0;

        if exec && body.len() > 1024 && entropy(body) > 7.2 {
            high_entropy_code += 1;
        }
        if exec && write {
            wx_sections.push(name.clone());
        }
        if is_suspicious_section_name(&name) {
            suspicious_names.push(name);
        }
    }

    push_section_hits(&mut hits, high_entropy_code, wx_sections, suspicious_names);
    hits
}

fn analyze_macho(data: &[u8]) -> Vec<DetectionHit> {
    let mut hits = Vec::new();
    let Ok(mach) = goblin::mach::Mach::parse(data) else {
        return hits;
    };

    let mut high_entropy_code = 0usize;
    let mut wx_sections = Vec::new();

    let mut inspect = |seg: &goblin::mach::segment::Segment| {
        let name = seg.name().unwrap_or("").to_string();
        let body = seg.data;
        let exec = seg.initprot & 0x4 != 0;
        let write = seg.initprot & 0x2 != 0;
        if exec && body.len() > 1024 && entropy(body) > 7.2 {
            high_entropy_code += 1;
        }
        if exec && write {
            wx_sections.push(name);
        }
    };

    match &mach {
        goblin::mach::Mach::Binary(macho) => {
            for seg in &macho.segments {
                inspect(seg);
            }
        }
        goblin::mach::Mach::Fat(multi) => {
            for arch in multi.into_iter().flatten() {
                if let goblin::mach::SingleArch::MachO(macho) = arch {
                    for seg in &macho.segments {
                        inspect(seg);
                    }
                }
            }
        }
    }

    if high_entropy_code > 0 {
        hits.push(DetectionHit {
            layer: DetectionLayer::Structural,
            detection_type: DetectionType::Packed,
            reason: format!("{high_entropy_code} executable segment(s) with very high entropy (likely packed/encrypted)"),
            family: None,
            confidence: 0.35,
            evidence: json!({ "high_entropy_segments": high_entropy_code }),
        });
    }
    if !wx_sections.is_empty() {
        hits.push(DetectionHit {
            layer: DetectionLayer::Structural,
            detection_type: DetectionType::Suspicious,
            reason: format!("writable+executable segment(s): {}", wx_sections.join(", ")),
            family: None,
            confidence: 0.3,
            evidence: json!({ "wx_segments": wx_sections }),
        });
    }
    hits
}

fn is_suspicious_section_name(name: &str) -> bool {
    matches!(
        name,
        "UPX0" | "UPX1" | "UPX2" | ".upx" | ".aspack" | ".adata" | "packed" | ".petite" | ".themida" | ".vmp0" | ".vmp1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_is_zero_for_constant() {
        assert!(entropy(&[0u8; 100]) < 0.001);
    }

    #[test]
    fn entropy_is_high_for_random_like() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(entropy(&data) > 7.9);
    }
}
