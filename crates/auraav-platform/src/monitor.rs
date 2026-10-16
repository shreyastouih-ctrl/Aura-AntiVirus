use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::{Duration, Instant};

use auraav_core::detection::Detector;
use auraav_core::types::Verdict;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};

/// Event emitted when a watched file is found to be malicious.
#[derive(Debug, Clone)]
pub struct MonitorEvent {
    pub path: PathBuf,
    pub verdict: Verdict,
    pub summary: String,
}

/// Watch the given directories and scan every newly-created/modified file.
///
/// `on_threat` is called for every file that is not `Clean`. Blocking; run it on
/// a dedicated thread. `sensitivity` controls heuristic aggressiveness.
pub fn watch<F>(
    detector: Detector,
    paths: Vec<PathBuf>,
    poll: Duration,
    mut on_threat: F,
) -> anyhow::Result<()>
where
    F: FnMut(MonitorEvent),
{
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })?;

    for path in &paths {
        if path.exists() {
            watcher.watch(path, RecursiveMode::Recursive)?;
        }
    }

    let mut last_seen: HashMap<PathBuf, Instant> = HashMap::new();
    loop {
        match rx.recv_timeout(poll) {
            Ok(Ok(event)) => {
                for path in event.paths {
                    if !path.is_file() {
                        continue;
                    }
                    // A single file write produces several notify events; skip
                    // repeats of the same path within a short cooldown window.
                    let now = Instant::now();
                    if let Some(prev) = last_seen.get(&path) {
                        if now.duration_since(*prev) < Duration::from_secs(2) {
                            continue;
                        }
                    }
                    last_seen.insert(path.clone(), now);
                    if last_seen.len() > 4096 {
                        last_seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));
                    }
                    if let Some(result) = detector.scan_file(&path) {
                        if result.verdict != Verdict::Clean {
                            let summary = result
                                .hits
                                .first()
                                .map(|h| h.reason.clone())
                                .unwrap_or_default();
                            on_threat(MonitorEvent {
                                path,
                                verdict: result.verdict,
                                summary,
                            });
                        }
                    }
                }
            }
            Ok(Err(_)) => {}
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

/// The set of directories worth watching for real-time protection.
pub fn default_watch_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = dirs::home_dir() {
        for sub in ["Downloads", "Desktop", "Documents", "tmp"] {
            let p = home.join(sub);
            if p.exists() {
                paths.push(p);
            }
        }
    }
    if let Ok(tmp) = std::env::var("TMPDIR") {
        let p = PathBuf::from(tmp);
        if p.exists() {
            paths.push(p);
        }
    } else {
        let p = Path::new("/tmp");
        if p.exists() {
            paths.push(p.to_path_buf());
        }
    }
    paths
}
