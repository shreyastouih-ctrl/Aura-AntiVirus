use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DriveKind {
    Fixed,
    Removable,
    Network,
    Optical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    pub name: String,
    pub mount_point: PathBuf,
    pub filesystem: String,
    pub kind: DriveKind,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
}

impl Drive {
    pub fn is_removable(&self) -> bool {
        matches!(self.kind, DriveKind::Removable)
    }
}

/// List mounted filesystems across platforms.
pub fn list_drives() -> Vec<Drive> {
    #[cfg(target_os = "linux")]
    {
        list_drives_linux()
    }
    #[cfg(target_os = "macos")]
    {
        list_drives_macos()
    }
    #[cfg(target_os = "windows")]
    {
        list_drives_windows()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// Only the removable/external drives.
pub fn list_removable_drives() -> Vec<Drive> {
    list_drives().into_iter().filter(|d| d.is_removable()).collect()
}

#[cfg(target_os = "linux")]
fn list_drives_linux() -> Vec<Drive> {
    let mut drives = Vec::new();
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return drives;
    };
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let (Some(device), Some(mount), Some(fs)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if !mount.starts_with('/') || is_virtual_fs(fs) || is_pseudo_path(mount) {
            continue;
        }
        let mount_point = PathBuf::from(unescape_octal(mount));
        let stats = filesystem_stats(&mount_point);
        drives.push(Drive {
            name: device.to_string(),
            mount_point,
            filesystem: fs.to_string(),
            kind: classify_linux_device(device),
            total_bytes: stats.map(|s| s.0),
            available_bytes: stats.map(|s| s.1),
        });
    }
    drives
}

#[cfg(target_os = "linux")]
fn classify_linux_device(device: &str) -> DriveKind {
    if device.starts_with("/dev/sd")
        || device.starts_with("/dev/mmcblk")
        || device.starts_with("/dev/sr")
    {
        DriveKind::Removable
    } else if device.starts_with("/dev/") {
        DriveKind::Fixed
    } else if device.contains(':') || device.starts_with("//") {
        DriveKind::Network
    } else {
        DriveKind::Unknown
    }
}

#[cfg(target_os = "linux")]
fn is_virtual_fs(fs: &str) -> bool {
    matches!(
        fs,
        "proc"
            | "sysfs"
            | "devtmpfs"
            | "devpts"
            | "tmpfs"
            | "cgroup"
            | "cgroup2"
            | "overlay"
            | "squashfs"
            | "ramfs"
            | "autofs"
            | "mqueue"
            | "pstore"
            | "bpf"
            | "tracefs"
            | "debugfs"
            | "securityfs"
            | "configfs"
            | "fusectl"
            | "binfmt_misc"
    )
}

#[cfg(target_os = "linux")]
fn is_pseudo_path(mount: &str) -> bool {
    mount.starts_with("/proc")
        || mount.starts_with("/sys")
        || mount.starts_with("/dev")
        || mount.starts_with("/run")
        || mount.starts_with("/snap")
}

#[cfg(target_os = "linux")]
fn unescape_octal(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(target_os = "linux")]
fn filesystem_stats(path: &std::path::Path) -> Option<(u64, u64)> {
    let out = std::process::Command::new("df").arg("-k").arg(path).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().nth(1)?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() >= 4 {
        let total = cols[1].parse::<u64>().ok()?.saturating_mul(1024);
        let avail = cols[3].parse::<u64>().ok()?.saturating_mul(1024);
        Some((total, avail))
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn list_drives_macos() -> Vec<Drive> {
    let mut drives = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/Volumes") {
        for entry in entries.flatten() {
            drives.push(Drive {
                name: entry.file_name().to_string_lossy().to_string(),
                mount_point: entry.path(),
                filesystem: String::new(),
                kind: DriveKind::Removable,
                total_bytes: None,
                available_bytes: None,
            });
        }
    }
    drives
}

#[cfg(target_os = "windows")]
fn list_drives_windows() -> Vec<Drive> {
    let mut drives = Vec::new();
    for letter in b'A'..=b'Z' {
        let root = format!("{}:\\", letter as char);
        let path = PathBuf::from(&root);
        if path.exists() {
            drives.push(Drive {
                name: root,
                mount_point: path,
                filesystem: String::new(),
                kind: DriveKind::Unknown,
                total_bytes: None,
                available_bytes: None,
            });
        }
    }
    drives
}
