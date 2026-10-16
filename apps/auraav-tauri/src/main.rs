#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use auraav_core::db::Db;
use auraav_core::quarantine::QuarantineManager;
use auraav_core::types::{HeuristicSensitivity, ScanConfig, ScanResult, Verdict};
use auraav_core::{Detector, ScanEngine, ScanProgress};
use crossbeam_channel::bounded;
use serde::Serialize;
use tauri::{Emitter, State};

struct AppState {
    config: Mutex<ScanConfig>,
}

#[derive(Serialize)]
struct ThreatSummary {
    path: String,
    verdict: String,
    confidence: f32,
    kind: String,
    reasons: Vec<String>,
}

fn summarize(result: &ScanResult) -> ThreatSummary {
    ThreatSummary {
        path: result.file_path.to_string_lossy().to_string(),
        verdict: result.verdict.name().to_string(),
        confidence: result.confidence,
        kind: format!("{:?}", result.file_kind),
        reasons: result.hits.iter().map(|h| h.reason.clone()).collect(),
    }
}

fn scan_paths_blocking(
    config: ScanConfig,
    paths: Vec<PathBuf>,
    app: tauri::AppHandle,
) -> Vec<ThreatSummary> {
    let engine = ScanEngine::new(config);
    let (tx, rx) = bounded::<ScanProgress>(256);

    let progress_app = app.clone();
    let pump = std::thread::spawn(move || {
        for p in rx {
            let _ = progress_app.emit("scan-progress", &p);
        }
    });

    let results = engine.scan_paths(&paths, Some(tx));
    let _ = pump.join();

    let threats: Vec<ThreatSummary> = results
        .iter()
        .filter(|r| r.verdict != Verdict::Clean)
        .map(summarize)
        .collect();
    let _ = app.emit("scan-complete", threats.len());
    threats
}

#[tauri::command]
async fn quick_scan(state: State<'_, AppState>, app: tauri::AppHandle) -> Result<Vec<ThreatSummary>, String> {
    let config = state.config.lock().unwrap().clone();
    let mut paths = Vec::new();
    if let Some(home) = dirs::home_dir() {
        for sub in ["Downloads", "Desktop", "Documents"] {
            let p = home.join(sub);
            if p.exists() {
                paths.push(p);
            }
        }
    }
    paths.push(PathBuf::from("/tmp"));
    Ok(scan_paths_blocking(config, paths, app))
}

#[tauri::command]
async fn full_scan(state: State<'_, AppState>, app: tauri::AppHandle) -> Result<Vec<ThreatSummary>, String> {
    let config = state.config.lock().unwrap().clone();
    Ok(scan_paths_blocking(config, vec![PathBuf::from("/")], app))
}

#[tauri::command]
async fn scan_paths(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    paths: Vec<String>,
) -> Result<Vec<ThreatSummary>, String> {
    let config = state.config.lock().unwrap().clone();
    let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    Ok(scan_paths_blocking(config, paths, app))
}

#[tauri::command]
async fn scan_drives(state: State<'_, AppState>, app: tauri::AppHandle) -> Result<Vec<ThreatSummary>, String> {
    let config = state.config.lock().unwrap().clone();
    let paths: Vec<PathBuf> = auraav_platform::list_removable_drives()
        .into_iter()
        .map(|d| d.mount_point)
        .collect();
    Ok(scan_paths_blocking(config, paths, app))
}

#[tauri::command]
fn list_drives() -> Vec<serde_json::Value> {
    auraav_platform::list_drives()
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "name": d.name,
                "mount_point": d.mount_point.to_string_lossy(),
                "kind": format!("{:?}", d.kind),
                "total_bytes": d.total_bytes,
                "available_bytes": d.available_bytes,
            })
        })
        .collect()
}

#[tauri::command]
fn quarantine_list() -> Result<Vec<serde_json::Value>, String> {
    let qm = QuarantineManager::open_default().map_err(|e| e.to_string())?;
    let entries = qm.list().map_err(|e| e.to_string())?;
    Ok(entries
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id.to_string(),
                "original_path": e.original_path.to_string_lossy(),
                "reason": e.reason,
                "family": e.family,
                "confidence": e.confidence,
                "quarantined_at": e.quarantined_at.to_rfc3339(),
            })
        })
        .collect())
}

#[tauri::command]
fn quarantine_restore(id: String) -> Result<(), String> {
    let qm = QuarantineManager::open_default().map_err(|e| e.to_string())?;
    let uuid = uuid::Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    qm.restore(uuid).map_err(|e| e.to_string())
}

#[tauri::command]
fn quarantine_delete(id: String) -> Result<(), String> {
    let qm = QuarantineManager::open_default().map_err(|e| e.to_string())?;
    let uuid = uuid::Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    qm.delete(uuid).map_err(|e| e.to_string())
}

#[tauri::command]
fn history(limit: usize, threats_only: bool) -> Result<Vec<serde_json::Value>, String> {
    let db = Db::open(Db::default_path()).map_err(|e| e.to_string())?;
    let rows = if threats_only {
        db.recent_threats(limit)
    } else {
        db.recent_results(limit)
    }
    .map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "file_path": r.file_path.to_string_lossy(),
                "hash": r.file_hash,
                "verdict": r.verdict,
                "confidence": r.confidence,
                "scanned_at": r.scanned_at,
            })
        })
        .collect())
}

#[tauri::command]
fn start_monitor(state: State<'_, AppState>, app: tauri::AppHandle) -> Result<(), String> {
    let config = state.config.lock().unwrap().clone();
    let db = auraav_core::signatures::load_default_db();
    let detector = Detector::new(db, config);
    let paths = auraav_platform::default_watch_paths();
    std::thread::spawn(move || {
        let _ = auraav_platform::watch(detector, paths, Duration::from_millis(500), move |event| {
            let _ = app.emit(
                "monitor-threat",
                serde_json::json!({
                    "path": event.path.to_string_lossy(),
                    "verdict": event.verdict.name(),
                    "summary": event.summary,
                }),
            );
        });
    });
    Ok(())
}

#[tauri::command]
fn get_config(state: State<'_, AppState>) -> ScanConfig {
    state.config.lock().unwrap().clone()
}

#[tauri::command]
fn set_config(state: State<'_, AppState>, config: ScanConfig) -> Result<(), String> {
    *state.config.lock().unwrap() = config;
    Ok(())
}

#[tauri::command]
fn set_sensitivity(state: State<'_, AppState>, level: String) -> Result<(), String> {
    let mut config = state.config.lock().unwrap();
    config.heuristic_sensitivity = match level.to_ascii_lowercase().as_str() {
        "off" => HeuristicSensitivity::Off,
        "medium" => HeuristicSensitivity::Medium,
        "high" => HeuristicSensitivity::High,
        _ => HeuristicSensitivity::Low,
    };
    Ok(())
}

#[tauri::command]
fn startup_status() -> bool {
    auraav_platform::is_startup_installed()
}

#[tauri::command]
fn startup_install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    auraav_platform::install_startup(&exe).map_err(|e| e.to_string())
}

#[tauri::command]
fn startup_uninstall() -> Result<(), String> {
    auraav_platform::uninstall_startup().map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            config: Mutex::new(ScanConfig::default()),
        })
        .invoke_handler(tauri::generate_handler![
            quick_scan,
            full_scan,
            scan_paths,
            scan_drives,
            list_drives,
            quarantine_list,
            quarantine_restore,
            quarantine_delete,
            history,
            start_monitor,
            get_config,
            set_config,
            startup_status,
            startup_install,
            startup_uninstall,
        ])
        .run(tauri::generate_context!())
        .expect("error while running auraAV");
}
