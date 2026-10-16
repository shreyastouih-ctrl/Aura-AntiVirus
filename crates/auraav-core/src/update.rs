//! Launch-time update checks against GitHub Releases.
//!
//! Checks are hash/version only. Signatures are refreshed into the per-user
//! data dir (no root needed); the app binary is replaced in place when it is
//! writable, otherwise the new build is staged and the user is told where it is.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

const REPO: &str = "shreyastouih-ctrl/Aura-AntiVirus";
const USER_AGENT: &str = concat!("auraAV/", env!("CARGO_PKG_VERSION"));
pub const DATA_ASSET: &str = "auraav-data.tar.gz";

#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

impl Release {
    /// e.g. "v0.3.0" -> "0.3.0"
    pub fn version(&self) -> String {
        self.tag_name.trim_start_matches('v').to_string()
    }

    pub fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }
}

/// Platform-specific release asset name, e.g. `auraav-0.3.0-linux-amd64.tar.gz`.
pub fn app_asset_name(version: &str) -> Option<String> {
    if cfg!(target_os = "linux") {
        Some(format!("auraav-{version}-linux-amd64.tar.gz"))
    } else if cfg!(target_os = "windows") {
        Some(format!("auraav-{version}-win64.zip"))
    } else if cfg!(target_os = "macos") {
        Some(format!("auraav-{version}-macos.tar.gz"))
    } else {
        None
    }
}

pub fn latest_release() -> Result<Release, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .user_agent(USER_AGENT)
        .build();
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    match agent.get(&url).call() {
        Ok(resp) => resp
            .into_json::<Release>()
            .map_err(|e| format!("bad release payload: {e}")),
        Err(e) => Err(format!("cannot reach GitHub: {e}")),
    }
}

/// True if `remote` is a higher semantic version than `current`.
pub fn is_newer(remote: &str, current: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.trim_start_matches('v')
            .split(['.', '-', '+'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    }
    let (r, c) = (parts(remote), parts(current));
    for i in 0..r.len().max(c.len()) {
        let a = r.get(i).copied().unwrap_or(0);
        let b = c.get(i).copied().unwrap_or(0);
        if a != b {
            return a > b;
        }
    }
    false
}

/// Per-user directory that holds refreshed signatures.
pub fn user_data_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("auraav").join("data"))
}

/// Directory where staged app builds are placed when the running binary is
/// not writable.
pub fn staging_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("auraav").join("update"))
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(120))
        .user_agent(USER_AGENT)
        .build();
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("download failed: {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(200 * 1024 * 1024)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;
    Ok(buf)
}

/// Download and unpack the signature data pack into the per-user data dir.
/// Returns the destination directory.
pub fn apply_data(release: &Release) -> Result<PathBuf, String> {
    let asset = release
        .asset(DATA_ASSET)
        .ok_or_else(|| format!("release has no {DATA_ASSET}"))?;
    let dest = user_data_dir().ok_or("cannot locate user data dir")?;
    let bytes = fetch_bytes(&asset.browser_download_url)?;
    let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(gz);
    fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    archive
        .unpack(&dest)
        .map_err(|e| format!("unpack data failed: {e}"))?;
    Ok(dest)
}

/// Download the app package and update the binaries.
///
/// If the currently-running executable is writable, it is replaced in place
/// (the running process keeps the old inode; the new build takes effect on the
/// next launch). Otherwise the new binaries are staged under
/// `user data dir/auraav/update/` and the staging path is returned.
pub enum AppUpdate {
    Replaced(Vec<PathBuf>),
    Staged(PathBuf),
    Unsupported,
}

pub fn apply_app(release: &Release) -> Result<AppUpdate, String> {
    let version = release.version();
    let Some(name) = app_asset_name(&version) else {
        return Ok(AppUpdate::Unsupported);
    };
    let asset = release
        .asset(&name)
        .ok_or_else(|| format!("release has no {name}"))?;
    let bytes = fetch_bytes(&asset.browser_download_url)?;

    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    extract_archive(&name, &bytes, tmp.path())?;

    // Collect the new binaries by base name.
    let mut new_bins: Vec<(String, PathBuf)> = Vec::new();
    for entry in walkdir::WalkDir::new(tmp.path()).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let fname = entry.file_name().to_string_lossy().to_string();
        if matches!(
            fname.as_str(),
            "auraav"
                | "auraav-cli"
                | "auraav-gui"
                | "auraav.exe"
                | "auraav-cli.exe"
                | "auraav-gui.exe"
        ) {
            new_bins.push((fname, entry.path().to_path_buf()));
        }
    }
    if new_bins.is_empty() {
        return Err("no binaries found in release package".into());
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_dir = exe.parent().map(Path::to_path_buf);
    let mut replaced = Vec::new();
    let mut staged = Vec::new();

    for (fname, src) in new_bins {
        let target = exe_dir.as_ref().map(|d| d.join(&fname));
        match target {
            Some(t) if can_write_dir(t.parent().unwrap_or(Path::new("."))) => {
                fs::copy(&src, &t).map_err(|e| format!("replace {fname}: {e}"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&t, fs::Permissions::from_mode(0o755));
                }
                replaced.push(t);
            }
            _ => staged.push((fname, src)),
        }
    }

    if !replaced.is_empty() {
        return Ok(AppUpdate::Replaced(replaced));
    }
    let dest = staging_dir().ok_or("cannot locate staging dir")?;
    fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    for (fname, src) in staged {
        fs::copy(&src, dest.join(&fname)).map_err(|e| e.to_string())?;
    }
    Ok(AppUpdate::Staged(dest))
}

fn can_write_dir(dir: &Path) -> bool {
    let probe = dir.join(".auraav-write-test");
    match fs::write(&probe, b"") {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn extract_archive(name: &str, bytes: &[u8], dest: &Path) -> Result<(), String> {
    if name.ends_with(".zip") {
        let reader = std::io::Cursor::new(bytes);
        let mut zip = zip::ZipArchive::new(reader).map_err(|e| format!("bad zip: {e}"))?;
        zip.extract(dest)
            .map_err(|e| format!("unzip failed: {e}"))?;
        Ok(())
    } else {
        let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
        let mut archive = tar::Archive::new(gz);
        archive
            .unpack(dest)
            .map_err(|e| format!("untar failed: {e}"))?;
        Ok(())
    }
}
