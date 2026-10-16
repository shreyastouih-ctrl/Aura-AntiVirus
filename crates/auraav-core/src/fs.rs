use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use walkdir::{DirEntry, WalkDir};

use crate::types::ScanConfig;

#[derive(Clone, Debug)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
}

/// Paths that belong to auraAV itself and must never be reported as threats:
/// the running executables, the signature data directory, and the user's
/// state directory (history DB + quarantine store). Excluding these removes
/// the "antivirus flags itself" false positives (its own binary embeds the
/// detection strings, and the rule files literally contain malware indicators).
#[derive(Default)]
struct SelfExclusion {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl SelfExclusion {
    fn discover() -> Self {
        let mut this = Self::default();

        if let Ok(exe) = std::env::current_exe() {
            let exe = exe.canonicalize().unwrap_or(exe);
            this.files.push(exe.clone());
            if let Some(bin) = exe.parent() {
                // Sibling auraAV binaries in the same install dir.
                for name in [
                    "auraav",
                    "auraav-cli",
                    "auraav-gui",
                    "auraav.exe",
                    "auraav-cli.exe",
                    "auraav-gui.exe",
                ] {
                    this.files.push(bin.join(name));
                }
                // Installed data dir: <prefix>/bin/../share/auraav
                if let Some(prefix) = bin.parent() {
                    this.dirs.push(prefix.join("share").join("auraav"));
                }
            }
        }

        if let Some(d) = crate::signatures::data_dir() {
            this.dirs.push(d.canonicalize().unwrap_or(d));
        }
        if let Some(d) = dirs::data_dir() {
            this.dirs.push(d.join("auraav"));
        }
        this
    }

    fn is_self(&self, path: &std::path::Path) -> bool {
        self.files.iter().any(|f| f == path) || self.dirs.iter().any(|d| path.starts_with(d))
    }
}

/// Rule/signature files are data, not scannable content: a rule file contains
/// the malware indicators by design, so scanning it self-matches.
fn is_signature_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".yar") || n.ends_with(".yara")
}

/// Build the glob set used to skip paths during traversal.
fn build_excludes(config: &ScanConfig) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for pat in &config.exclude_patterns {
        if let Ok(glob) = Glob::new(pat) {
            builder.add(glob);
        }
        // Also treat a bare directory name pattern as "any path component".
        if let Ok(glob) = Glob::new(&format!("**/{pat}/**")) {
            builder.add(glob);
        }
    }
    builder.build().unwrap_or_else(|_| GlobSet::empty())
}

/// Walk the given roots and return every regular file that passes the excludes.
pub fn scan_paths(paths: &[PathBuf], config: &ScanConfig) -> Vec<FileInfo> {
    let excludes = build_excludes(config);
    let self_ex = SelfExclusion::discover();
    let mut results = Vec::new();
    for root in paths {
        if !root.exists() {
            continue;
        }
        let root = root.canonicalize().unwrap_or_else(|_| root.clone());
        let walker = WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| should_descend(e, config, &excludes, &self_ex));
        for entry in walker.flatten() {
            if entry.file_type().is_file() {
                if let Some(info) = file_info(&entry, config, &excludes, &self_ex) {
                    results.push(info);
                }
            }
        }
    }
    results
}

fn file_info(
    entry: &DirEntry,
    config: &ScanConfig,
    excludes: &GlobSet,
    self_ex: &SelfExclusion,
) -> Option<FileInfo> {
    let path = entry.path();
    if excludes.is_match(path) || self_ex.is_self(path) {
        return None;
    }
    let name = entry.file_name().to_string_lossy();
    if is_signature_file(&name) {
        return None;
    }
    if !config.include_hidden && name.starts_with('.') {
        return None;
    }
    let size = entry.metadata().ok()?.len();
    if size > config.max_file_size_mb.saturating_mul(1024 * 1024) {
        return None;
    }
    Some(FileInfo {
        path: path.to_path_buf(),
        size,
    })
}

fn should_descend(
    entry: &DirEntry,
    _config: &ScanConfig,
    excludes: &GlobSet,
    self_ex: &SelfExclusion,
) -> bool {
    let path = entry.path();
    // Never recurse into virtual/pseudo filesystems.
    if is_pseudo_fs(path) {
        return false;
    }
    if entry.file_type().is_dir() {
        if excludes.is_match(path) || self_ex.is_self(path) {
            return false;
        }
    }
    true
}

fn is_pseudo_fs(path: &Path) -> bool {
    for prefix in ["/proc", "/sys", "/dev", "/run", "/snap"] {
        if path.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Default locations for a quick scan.
pub fn default_quick_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = dirs::home_dir() {
        for sub in ["Downloads", "Desktop", "Documents"] {
            let p = home.join(sub);
            if p.exists() {
                paths.push(p);
            }
        }
    }
    if Path::new("/tmp").exists() {
        paths.push(PathBuf::from("/tmp"));
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_paths_are_existing() {
        for p in default_quick_paths() {
            assert!(p.exists());
        }
    }

    #[test]
    fn signature_files_are_detected() {
        assert!(is_signature_file("example_rules.yar"));
        assert!(is_signature_file("RULES.YARA"));
        assert!(!is_signature_file("malware.bin"));
    }

    #[test]
    fn scan_skips_signature_files_but_keeps_others() {
        let dir = std::env::temp_dir().join(format!("auraav-fs-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rules.yar"), b"rule x { condition: true }").unwrap();
        std::fs::write(dir.join("sample.bin"), b"not malware").unwrap();

        let found = scan_paths(&[dir.clone()], &ScanConfig::default());
        let names: Vec<_> = found
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"sample.bin".to_string()));
        assert!(!names.iter().any(|n| n.ends_with(".yar")));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
