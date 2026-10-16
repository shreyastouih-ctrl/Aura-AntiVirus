use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use walkdir::{DirEntry, WalkDir};

use crate::types::ScanConfig;

#[derive(Clone, Debug)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
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
    let mut results = Vec::new();
    for root in paths {
        if !root.exists() {
            continue;
        }
        let walker = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| should_descend(e, config, &excludes));
        for entry in walker.flatten() {
            if entry.file_type().is_file() {
                if let Some(info) = file_info(&entry, config, &excludes) {
                    results.push(info);
                }
            }
        }
    }
    results
}

fn file_info(entry: &DirEntry, config: &ScanConfig, excludes: &GlobSet) -> Option<FileInfo> {
    let path = entry.path();
    if excludes.is_match(path) {
        return None;
    }
    let name = entry.file_name().to_string_lossy();
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

fn should_descend(entry: &DirEntry, _config: &ScanConfig, excludes: &GlobSet) -> bool {
    let path = entry.path();
    // Never recurse into virtual/pseudo filesystems.
    if is_pseudo_fs(path) {
        return false;
    }
    if entry.file_type().is_dir() && excludes.is_match(path) {
        return false;
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
}
