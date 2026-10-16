use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileKind {
    Pe,
    Elf,
    MachO,
    Script(ScriptKind),
    Archive,
    Document,
    Text,
    Binary,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptKind {
    Shell,
    Python,
    JavaScript,
    TypeScript,
    PowerShell,
    Batch,
    Vbs,
    Perl,
    Ruby,
    Php,
    Lua,
    Unknown,
}

impl ScriptKind {
    pub fn is_script(self) -> bool {
        !matches!(self, ScriptKind::Unknown)
    }

    pub fn name(self) -> &'static str {
        match self {
            ScriptKind::Shell => "shell",
            ScriptKind::Python => "python",
            ScriptKind::JavaScript => "javascript",
            ScriptKind::TypeScript => "typescript",
            ScriptKind::PowerShell => "powershell",
            ScriptKind::Batch => "batch",
            ScriptKind::Vbs => "vbscript",
            ScriptKind::Perl => "perl",
            ScriptKind::Ruby => "ruby",
            ScriptKind::Php => "php",
            ScriptKind::Lua => "lua",
            ScriptKind::Unknown => "unknown",
        }
    }
}

impl FileKind {
    /// True for anything that can carry native code.
    pub fn is_executable(self) -> bool {
        matches!(self, FileKind::Pe | FileKind::Elf | FileKind::MachO)
    }

    pub fn is_script(self) -> bool {
        matches!(self, FileKind::Script(_))
    }

    /// Files worth running the heavier analysis (disasm, CFG, similarity) on.
    pub fn deserves_deep_analysis(self) -> bool {
        self.is_executable() || self.is_script() || matches!(self, FileKind::Binary)
    }
}

/// Detect the file kind from leading bytes plus the path extension.
pub fn classify_file(path: &Path, data: &[u8]) -> FileKind {
    if let Some(kind) = detect_native(data) {
        return kind;
    }
    if let Some(kind) = detect_archive_magic(data) {
        return kind;
    }
    if let Some(kind) = detect_document_magic(data) {
        return kind;
    }

    let textual = looks_textual(data);

    if textual {
        if let Some(script) = detect_shebang(data) {
            return FileKind::Script(script);
        }
        if let Some(script) = script_by_ext(path) {
            return FileKind::Script(script);
        }
        return FileKind::Text;
    }

    FileKind::Binary
}

fn detect_native(data: &[u8]) -> Option<FileKind> {
    if data.len() > 0x40 && data[0] == b'M' && data[1] == b'Z' {
        if let Some(off) = read_u32_le(data, 0x3c) {
            let off = off as usize;
            if off + 4 <= data.len() && &data[off..off + 4] == b"PE\0\0" {
                return Some(FileKind::Pe);
            }
        }
    }
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return Some(FileKind::Elf);
    }
    if data.len() >= 4 && is_macho_magic(&data[..4]) {
        return Some(FileKind::MachO);
    }
    None
}

fn is_macho_magic(m: &[u8]) -> bool {
    matches!(
        m,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
    )
}

fn detect_archive_magic(data: &[u8]) -> Option<FileKind> {
    let archive = data.len() >= 4
        && (data.starts_with(b"PK\x03\x04")
            || data.starts_with(b"PK\x05\x06")
            || data.starts_with(b"Rar!")
            || data.starts_with(b"7z\xbc\xaf\x27\x1c")
            || data.starts_with(b"\x1f\x8b")
            || data.starts_with(b"BZh")
            || data.starts_with(b"\xfd7zXZ"));
    archive.then_some(FileKind::Archive)
}

fn detect_document_magic(data: &[u8]) -> Option<FileKind> {
    let doc = data.len() >= 4
        && (data.starts_with(b"%PDF") || data.starts_with(b"\xd0\xcf\x11\xe0"));
    doc.then_some(FileKind::Document)
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]))
}

fn looks_textual(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(8192)];
    if sample.is_empty() {
        return true;
    }
    let mut control = 0usize;
    for &b in sample {
        if b == 0 {
            return false;
        }
        if b < 0x09 || (b > 0x0d && b < 0x20) {
            control += 1;
        }
    }
    (control as f32 / sample.len() as f32) < 0.05
}

fn detect_shebang(data: &[u8]) -> Option<ScriptKind> {
    if !data.starts_with(b"#!") {
        return None;
    }
    let end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let line = String::from_utf8_lossy(&data[2..end]).to_lowercase();
    let kind = if line.contains("python") {
        ScriptKind::Python
    } else if line.contains("node") || line.contains("deno") || line.contains("bun") {
        ScriptKind::JavaScript
    } else if line.contains("pwsh") || line.contains("powershell") {
        ScriptKind::PowerShell
    } else if line.contains("perl") {
        ScriptKind::Perl
    } else if line.contains("ruby") {
        ScriptKind::Ruby
    } else if line.contains("php") {
        ScriptKind::Php
    } else if line.contains("lua") {
        ScriptKind::Lua
    } else if line.contains("sh")
        || line.contains("bash")
        || line.contains("zsh")
        || line.contains("dash")
        || line.contains("ksh")
    {
        ScriptKind::Shell
    } else {
        ScriptKind::Unknown
    };
    Some(kind)
}

fn script_by_ext(path: &Path) -> Option<ScriptKind> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let kind = match ext.as_str() {
        "sh" | "bash" | "zsh" | "ksh" | "dash" => ScriptKind::Shell,
        "py" | "pyw" | "pyi" => ScriptKind::Python,
        "js" | "mjs" | "cjs" | "jsx" => ScriptKind::JavaScript,
        "ts" | "tsx" => ScriptKind::TypeScript,
        "ps1" | "psm1" | "psd1" => ScriptKind::PowerShell,
        "bat" | "cmd" => ScriptKind::Batch,
        "vbs" | "vbe" | "wsf" => ScriptKind::Vbs,
        "pl" | "pm" => ScriptKind::Perl,
        "rb" => ScriptKind::Ruby,
        "php" | "phtml" => ScriptKind::Php,
        "lua" => ScriptKind::Lua,
        _ => return None,
    };
    Some(kind)
}

pub fn has_executable_ext(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(e) => matches!(
            e.to_ascii_lowercase().as_str(),
            "exe" | "dll" | "sys" | "scr" | "com" | "cpl" | "ocx" | "drv" | "efi" | "so" | "dylib"
        ),
        None => false,
    }
}
