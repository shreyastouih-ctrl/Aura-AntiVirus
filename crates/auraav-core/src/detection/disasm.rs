use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

use crate::filetype::FileKind;

use super::similarity::FuzzyDigest;

/// Fingerprint of *normalized* x86/x86-64 instructions used to catch
/// metamorphic code that keeps the same mnemonic structure while renaming
/// registers, changing immediates, or inserting junk.
#[derive(Debug, Clone)]
pub struct CodeFingerprint {
    /// Order-preserving fuzzy digest of the mnemonic stream.
    pub mnemonic_stream: FuzzyDigest,
    /// Order-independent fuzzy digest of the mnemonic *set*.
    pub mnemonic_set: FuzzyDigest,
    pub instruction_count: usize,
    pub branch_count: usize,
    pub block_count: usize,
}

impl CodeFingerprint {
    pub fn similarity(&self, other: &CodeFingerprint) -> f32 {
        0.4 * self.mnemonic_stream.similarity(&other.mnemonic_stream)
            + 0.6 * self.mnemonic_set.similarity(&other.mnemonic_set)
    }
}

/// Extract the code section bytes plus the instruction bitness for a binary.
pub fn extract_code(kind: FileKind, data: &[u8]) -> Option<(Vec<u8>, u32)> {
    match kind {
        FileKind::Pe => extract_pe_code(data),
        FileKind::Elf => extract_elf_code(data),
        FileKind::MachO => extract_macho_code(data),
        _ => None,
    }
}

fn extract_pe_code(data: &[u8]) -> Option<(Vec<u8>, u32)> {
    let pe = goblin::pe::PE::parse(data).ok()?;
    let bitness = match pe.header.coff_header.machine {
        0x014c => 32,
        _ => 64,
    };
    for section in &pe.sections {
        let name = section.name().unwrap_or("").trim_end_matches('\0');
        let is_code = section.characteristics & 0x0000_0020 != 0;
        if name == ".text" || name.starts_with(".text") || is_code {
            let start = section.pointer_to_raw_data as usize;
            let end = (start + section.size_of_raw_data as usize).min(data.len());
            if start < end {
                return Some((data[start..end].to_vec(), bitness));
            }
        }
    }
    None
}

fn extract_elf_code(data: &[u8]) -> Option<(Vec<u8>, u32)> {
    let elf = goblin::elf::Elf::parse(data).ok()?;
    let bitness = if elf.is_64 { 64 } else { 32 };
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name == ".text" || name.starts_with(".text") {
                let start = section.sh_offset as usize;
                let end = (start + section.sh_size as usize).min(data.len());
                if start < end {
                    return Some((data[start..end].to_vec(), bitness));
                }
            }
        }
    }
    None
}

fn extract_macho_code(data: &[u8]) -> Option<(Vec<u8>, u32)> {
    let mach = goblin::mach::Mach::parse(data).ok()?;
    let macho = match &mach {
        goblin::mach::Mach::Binary(m) => m,
        goblin::mach::Mach::Fat(_) => return None,
    };
    let bitness = if macho.is_64 { 64 } else { 32 };
    for seg in &macho.segments {
        let name = seg.name().unwrap_or("");
        if (name == "__TEXT" || name == "__text") && !seg.data.is_empty() {
            return Some((seg.data.to_vec(), bitness));
        }
    }
    None
}

/// Build a code fingerprint for a native binary, if it has decodable code.
pub fn fingerprint(kind: FileKind, data: &[u8]) -> Option<CodeFingerprint> {
    let (code, bitness) = extract_code(kind, data)?;
    if code.len() < 64 {
        return None;
    }
    normalize_and_fingerprint(&code, bitness)
}

/// Decode a code buffer and build mnemonic-level fingerprints.
pub fn normalize_and_fingerprint(code: &[u8], bitness: u32) -> Option<CodeFingerprint> {
    if !matches!(bitness, 16 | 32 | 64) {
        return None;
    }
    let mut decoder = Decoder::with_ip(bitness, code, 0, DecoderOptions::NONE);
    let mut instr = Instruction::default();

    let mut symbols: Vec<u32> = Vec::with_capacity(1024);
    let mut branch_count = 0usize;
    let mut block_count = 1usize;

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        symbols.push(instr.mnemonic() as u32);
        if instr.flow_control() != FlowControl::Next {
            branch_count += 1;
            block_count += 1;
        }
    }

    if symbols.len() < 8 {
        return None;
    }

    // Serialize each mnemonic as 4 little-endian bytes; the 4-byte fuzzy window
    // therefore hashes exactly one symbol at a time.
    let stream_bytes: Vec<u8> = symbols.iter().flat_map(|s| s.to_le_bytes()).collect();
    let mut unique = symbols.clone();
    unique.sort_unstable();
    unique.dedup();
    let set_bytes: Vec<u8> = unique.iter().flat_map(|s| s.to_le_bytes()).collect();

    Some(CodeFingerprint {
        mnemonic_stream: FuzzyDigest::compute(&stream_bytes),
        mnemonic_set: FuzzyDigest::compute(&set_bytes),
        instruction_count: symbols.len(),
        branch_count,
        block_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small but >8 instruction routine (mov/push/add/nop/.../ret).
    fn routine(mov_imm: u32, mov2_imm: u32, reg1: u8, reg2: u8) -> Vec<u8> {
        let mut code = vec![
            0xb8 | reg1 & 0x7, 0, 0, 0, 0, // mov reg, imm32
            0xbb | reg2 & 0x7, 0, 0, 0, 0, // mov reg2, imm32
            0x50, // push rax
            0x58, // pop rax
            0x01, 0xd8, // add eax, ebx
            0x90, 0x90, 0x90, 0x90, // nops
            0xc3, // ret
        ];
        code[1..5].copy_from_slice(&mov_imm.to_le_bytes());
        code[6..10].copy_from_slice(&mov2_imm.to_le_bytes());
        code
    }

    #[test]
    fn identical_code_is_identical() {
        let code = routine(1, 2, 0, 3);
        let a = normalize_and_fingerprint(&code, 64).unwrap();
        let b = normalize_and_fingerprint(&code, 64).unwrap();
        assert_eq!(a.similarity(&b), 1.0);
    }

    #[test]
    fn register_renaming_keeps_similarity() {
        // Same mnemonics, different registers/immediates (metamorphic-style).
        let a = routine(1, 2, 0, 3);
        let b = routine(9, 7, 1, 2);
        let fa = normalize_and_fingerprint(&a, 64).unwrap();
        let fb = normalize_and_fingerprint(&b, 64).unwrap();
        assert!(fa.similarity(&fb) > 0.8, "sim={}", fa.similarity(&fb));
    }

    #[test]
    fn tiny_code_rejected() {
        assert!(normalize_and_fingerprint(&[0x90; 4], 64).is_none());
    }
}
