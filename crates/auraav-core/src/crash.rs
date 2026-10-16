//! Crash reporting: capture panics locally, then deliver them as a pre-filled
//! GitHub issue. Reports are queued on disk while offline and opened for the
//! user as soon as the machine is online again.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;

const REPO: &str = "shreyastouih-ctrl/Aura-AntiVirus";
const USER_AGENT: &str = concat!("auraAV/", env!("CARGO_PKG_VERSION"));

pub fn crashes_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("auraav").join("crashes"))
}

/// Install a panic hook that writes a report to disk before the process dies.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(path) = write_report(info) {
            eprintln!("auraAV: crash report saved to {}", path.display());
        }
        default(info);
    }));
}

fn payload_string(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "(non-string panic payload)".to_string()
    }
}

fn location(info: &std::panic::PanicHookInfo<'_>) -> String {
    info.location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_default()
}

fn write_report(info: &std::panic::PanicHookInfo<'_>) -> Option<PathBuf> {
    let dir = crashes_dir()?;
    fs::create_dir_all(&dir).ok()?;
    let now = Utc::now();
    let body = format!(
        "auraAV crash report\n\
         version: {ver}\n\
         os: {os} {arch}\n\
         time: {time}\n\
         location: {loc}\n\
         message: {msg}\n\n\
         backtrace:\n{bt}\n",
        ver = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        time = now.to_rfc3339(),
        loc = location(info),
        msg = payload_string(info.payload()),
        bt = std::backtrace::Backtrace::force_capture(),
    );
    let name = format!("crash-{}.txt", now.format("%Y%m%d-%H%M%S-%3f"));
    let path = dir.join(name);
    fs::write(&path, body).ok()?;
    Some(path)
}

fn is_pending(p: &Path) -> bool {
    p.extension().and_then(|e| e.to_str()) == Some("txt")
}

/// Number of crash reports waiting to be delivered.
pub fn pending_count() -> usize {
    let Some(dir) = crashes_dir() else { return 0 };
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| is_pending(&e.path()))
        .count()
}

/// Open a pre-filled GitHub issue per queued report once online. Returns the
/// number of reports handed to the browser. No-op while offline.
pub fn flush_pending() -> usize {
    let Some(dir) = crashes_dir() else { return 0 };
    let pending: Vec<PathBuf> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_pending(p))
        .collect();
    if pending.is_empty() || !is_online() {
        return 0;
    }
    let mut sent = 0;
    for path in pending {
        let Ok(report) = fs::read_to_string(&path) else {
            continue;
        };
        if open_issue(&report) {
            let _ = fs::rename(&path, path.with_extension("sent"));
            sent += 1;
        }
    }
    sent
}

fn is_online() -> bool {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(4))
        .user_agent(USER_AGENT)
        .build();
    agent.head("https://api.github.com").call().is_ok()
}

fn open_issue(report: &str) -> bool {
    let body = format!(
        "<!-- Remove anything you are not comfortable sharing before submitting. -->\n\n\
         ```\n{report}\n```\n"
    );
    let url = format!(
        "https://github.com/{REPO}/issues/new?title={}&body={}&labels={}",
        pct("Crash report"),
        pct(&body),
        pct("crash"),
    );
    open_in_browser(&url)
}

fn open_in_browser(url: &str) -> bool {
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// Minimal percent-encoding for query values (RFC 3986 unreserved set kept).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding() {
        assert_eq!(pct("a b"), "a%20b");
        assert_eq!(pct("x/y?z"), "x%2Fy%3Fz");
    }

    #[test]
    fn pending_detection() {
        assert!(is_pending(Path::new("crash-1.txt")));
        assert!(!is_pending(Path::new("crash-1.sent")));
    }
}
