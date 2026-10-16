use std::path::PathBuf;

/// Install auraAV to run at login/startup for the current user.
pub fn install_startup(binary: &PathBuf) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        install_startup_linux(binary)
    }
    #[cfg(target_os = "macos")]
    {
        install_startup_macos(binary)
    }
    #[cfg(target_os = "windows")]
    {
        install_startup_windows(binary)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = binary;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported platform",
        ))
    }
}

/// Remove the startup entry.
pub fn uninstall_startup() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = linux_service_path();
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let path = macos_plist_path();
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        windows_delete_run_key()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(())
    }
}

pub fn is_startup_installed() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux_service_path().exists()
    }
    #[cfg(target_os = "macos")]
    {
        macos_plist_path().exists()
    }
    #[cfg(target_os = "windows")]
    {
        windows_run_key_exists()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn linux_service_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_default().join(".config"));
    base.join("systemd/user/auraav.service")
}

#[cfg(target_os = "linux")]
fn install_startup_linux(binary: &PathBuf) -> std::io::Result<()> {
    let path = linux_service_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let unit = format!(
        "[Unit]\n\
         Description=auraAV background protection\n\
         After=default.target\n\n\
         [Service]\n\
         ExecStart={} daemon\n\
         Restart=on-failure\n\
         RestartSec=10\n\n\
         [Install]\n\
         WantedBy=default.target\n",
        binary.display()
    );
    std::fs::write(&path, unit)?;
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", "auraav.service"])
        .status();
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_plist_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("Library/LaunchAgents/com.auraav.agent.plist")
}

#[cfg(target_os = "macos")]
fn install_startup_macos(binary: &PathBuf) -> std::io::Result<()> {
    let path = macos_plist_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.auraav.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>monitor</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#,
        binary.display()
    );
    std::fs::write(macos_plist_path(), plist)
}

#[cfg(target_os = "windows")]
fn install_startup_windows(binary: &PathBuf) -> std::io::Result<()> {
    use std::process::Command;
    let exe = binary.display().to_string();
    let status = Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "auraAV",
            "/t",
            "REG_SZ",
            "/d",
            &exe,
            "/f",
        ])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "failed to write Run registry key",
        ))
    }
}

#[cfg(target_os = "windows")]
fn windows_delete_run_key() -> std::io::Result<()> {
    use std::process::Command;
    Command::new("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "auraAV",
            "/f",
        ])
        .status()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_run_key_exists() -> bool {
    use std::process::Command;
    Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "auraAV",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
