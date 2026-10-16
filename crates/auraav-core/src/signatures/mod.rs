pub mod fingerprints;
pub mod rules;

pub use fingerprints::{CodeSignature, FuzzySignature};
pub use rules::{
    contains_bytes, parse_rules, HashSignature, Rule, RuleCondition, RulePattern, SignatureDb,
};

use std::path::{Path, PathBuf};

/// True if `dir` looks like an auraAV signature pack.
fn has_pack(dir: &Path) -> bool {
    dir.join("signatures").exists() || dir.join("rules").exists()
}

/// Locate the signature data directory.
///
/// Order of preference:
/// 1. `$AURAAV_DATA_DIR` if set.
/// 2. `<cwd>/data` when a signature/rule pack exists (dev/portable use).
/// 3. Next to the executable: `<exe_dir>/data` or `<exe_dir>/../share/auraav/data`
///    (installed layouts, e.g. `/usr/bin/auraav` + `/usr/share/auraav/data`).
/// 4. The user data dir (`~/.local/share/auraav/data` on Linux).
pub fn data_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("AURAAV_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }
    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("data");
        if has_pack(&candidate) {
            return Some(candidate);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin) = exe.parent() {
            let candidates = [
                bin.join("data"),
                bin.join("..").join("share").join("auraav").join("data"),
            ];
            for candidate in candidates {
                if has_pack(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }
    dirs::data_dir().map(|d| d.join("auraav").join("data"))
}

/// Build a [`SignatureDb`], loading every signature and rule pack we can find.
///
/// This never fails hard: a missing or unreadable pack is logged and skipped so
/// detection still works with whatever is available.
pub fn load_default_db() -> SignatureDb {
    let mut db = SignatureDb::new();
    if let Some(dir) = data_dir() {
        for sub in ["signatures", "rules", "fingerprints"] {
            let subdir = dir.join(sub);
            match db.load_dir(&subdir) {
                Ok((h, r, f, c)) => {
                    if h + r + f + c > 0 {
                        tracing::info!(
                            "loaded {h} hashes, {r} rules, {f} fuzzy, {c} code fingerprints from {}",
                            subdir.display()
                        );
                    }
                }
                Err(e) => tracing::debug!("no signature pack at {}: {e}", subdir.display()),
            }
        }
    } else {
        tracing::warn!("could not determine signature data directory");
    }
    db
}
