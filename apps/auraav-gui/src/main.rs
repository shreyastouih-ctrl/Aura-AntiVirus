#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::time::Duration;

use auraav_core::db::Db;
use auraav_core::quarantine::QuarantineManager;
use auraav_core::signatures::load_default_db;
use auraav_core::types::{HeuristicSensitivity, ScanConfig, ScanResult, Verdict};
use auraav_core::{Detector, ScanEngine, ScanProgress};
use auraav_platform::MonitorEvent;
use crossbeam_channel::{unbounded, Receiver, Sender};
use eframe::egui::{self, Color32, RichText};
use uuid::Uuid;

const GREEN: Color32 = Color32::from_rgb(74, 222, 128);
const AMBER: Color32 = Color32::from_rgb(251, 191, 36);
const RED: Color32 = Color32::from_rgb(248, 113, 113);
const MUTED: Color32 = Color32::from_rgb(148, 163, 184);

enum ScanMsg {
    Progress(ScanProgress),
    Done(Vec<ScanResult>),
}

struct QuarantineRow {
    id: Uuid,
    original_path: String,
    reason: String,
    quarantined_at: String,
}

struct HistoryRow {
    verdict: String,
    file_path: String,
    scanned_at: String,
}

fn quick_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = dirs::home_dir() {
        for sub in ["Downloads", "Desktop", "Documents"] {
            let p = home.join(sub);
            if p.exists() {
                paths.push(p);
            }
        }
    }
    if paths.is_empty() {
        paths.push(PathBuf::from("/tmp"));
    }
    paths
}

struct App {
    config: ScanConfig,
    status: String,

    scan_tx: Sender<ScanMsg>,
    scan_rx: Receiver<ScanMsg>,
    scan_running: bool,
    progress: ScanProgress,
    results: Vec<ScanResult>,

    monitor_tx: Sender<MonitorEvent>,
    monitor_rx: Receiver<MonitorEvent>,
    monitor_on: bool,

    quarantine: Vec<QuarantineRow>,
    history: Vec<HistoryRow>,
    history_threats_only: bool,

    path_input: String,
}

impl App {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (scan_tx, scan_rx) = unbounded();
        let (monitor_tx, monitor_rx) = unbounded();
        let mut app = Self {
            config: ScanConfig::default(),
            scan_tx,
            scan_rx,
            monitor_tx,
            monitor_rx,
            scan_running: false,
            progress: ScanProgress {
                files_scanned: 0,
                files_total: 0,
                current_path: None,
                threats_found: 0,
                done: false,
            },
            results: Vec::new(),
            monitor_on: false,
            quarantine: Vec::new(),
            history: Vec::new(),
            history_threats_only: true,
            status: "Ready to scan.".to_string(),
            path_input: dirs::home_dir()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".to_string()),
        };
        app.refresh_quarantine();
        app.refresh_history();
        app
    }

    fn start_scan(&mut self, label: &str, paths: Vec<PathBuf>) {
        if self.scan_running {
            return;
        }
        self.scan_running = true;
        self.results.clear();
        self.progress = ScanProgress {
            files_scanned: 0,
            files_total: 0,
            current_path: None,
            threats_found: 0,
            done: false,
        };
        self.status = format!("{label}: scanning...");

        let config = self.config.clone();
        let tx = self.scan_tx.clone();
        std::thread::spawn(move || {
            let engine = ScanEngine::new(config);
            let (ptx, prx) = unbounded::<ScanProgress>();
            let pump_tx = tx.clone();
            let pump = std::thread::spawn(move || {
                for p in prx {
                    let _ = pump_tx.send(ScanMsg::Progress(p));
                }
            });
            let results = engine.scan_paths(&paths, Some(ptx));
            let _ = pump.join();
            if let Ok(db) = Db::open(Db::default_path()) {
                for r in &results {
                    let _ = db.save_result(r);
                }
            }
            let _ = tx.send(ScanMsg::Done(results));
        });
    }

    fn start_monitor(&mut self) {
        if self.monitor_on {
            return;
        }
        let detector = Detector::new(load_default_db(), self.config.clone());
        let paths = auraav_platform::default_watch_paths();
        let tx = self.monitor_tx.clone();
        std::thread::spawn(move || {
            let _ = auraav_platform::watch(detector, paths, Duration::from_secs(1), move |ev| {
                let _ = tx.send(ev);
            });
        });
        self.monitor_on = true;
        self.status = "Real-time protection active.".to_string();
    }

    fn refresh_quarantine(&mut self) {
        self.quarantine.clear();
        if let Ok(qm) = QuarantineManager::open_default() {
            if let Ok(entries) = qm.list() {
                for e in entries {
                    self.quarantine.push(QuarantineRow {
                        id: e.id,
                        original_path: e.original_path.to_string_lossy().to_string(),
                        reason: e.reason,
                        quarantined_at: e.quarantined_at.format("%Y-%m-%d %H:%M").to_string(),
                    });
                }
            }
        }
    }

    fn refresh_history(&mut self) {
        self.history.clear();
        if let Ok(db) = Db::open(Db::default_path()) {
            let rows = if self.history_threats_only {
                db.recent_threats(200)
            } else {
                db.recent_results(200)
            };
            if let Ok(rows) = rows {
                for r in rows {
                    self.history.push(HistoryRow {
                        verdict: r.verdict,
                        file_path: r.file_path.to_string_lossy().to_string(),
                        scanned_at: r.scanned_at.chars().take(19).collect(),
                    });
                }
            }
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let mut got = false;
        while let Ok(msg) = self.scan_rx.try_recv() {
            got = true;
            match msg {
                ScanMsg::Progress(p) => self.progress = p,
                ScanMsg::Done(results) => {
                    self.scan_running = false;
                    let threats = results.iter().filter(|r| r.is_threat()).count();
                    self.results = results;
                    self.status = format!("Scan complete - {threats} threat(s) found.");
                    self.refresh_history();
                }
            }
        }
        while let Ok(ev) = self.monitor_rx.try_recv() {
            got = true;
            self.status = format!("Real-time: {} - {}", ev.verdict.name(), ev.path.display());
        }
        if self.scan_running || got {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll(ui.ctx());

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading(RichText::new("aura").color(GREEN).strong());
            ui.label(RichText::new("AV").strong());
            ui.separator();
            ui.label(RichText::new("unified, offline-first antivirus").color(MUTED));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let sens = self.config.heuristic_sensitivity;
                egui::ComboBox::from_id_salt("sens")
                    .selected_text(format!("Sensitivity: {sens:?}"))
                    .show_ui(ui, |ui| {
                        for s in [
                            HeuristicSensitivity::Off,
                            HeuristicSensitivity::Low,
                            HeuristicSensitivity::Medium,
                            HeuristicSensitivity::High,
                        ] {
                            ui.selectable_value(
                                &mut self.config.heuristic_sensitivity,
                                s,
                                format!("{s:?}"),
                            );
                        }
                    });
                ui.checkbox(&mut self.config.enable_cloud, "Cloud check")
                    .on_hover_text(
                        "Confirm suspicious/malicious files by SHA-256 online (MalwareBazaar)",
                    );
            });
        });
        ui.separator();

        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let quick = ui.add_enabled(!self.scan_running, egui::Button::new("Quick Scan"));
                if quick.clicked() {
                    self.start_scan("Quick scan", quick_paths());
                }
                let full = ui.add_enabled(!self.scan_running, egui::Button::new("Full Scan"));
                if full.clicked() {
                    self.start_scan("Full scan", vec![PathBuf::from("/")]);
                }
                let drives = ui.add_enabled(!self.scan_running, egui::Button::new("Scan Drives"));
                if drives.clicked() {
                    let paths: Vec<PathBuf> = auraav_platform::list_removable_drives()
                        .into_iter()
                        .map(|d| d.mount_point)
                        .collect();
                    if paths.is_empty() {
                        self.status = "No removable drives detected.".to_string();
                    } else {
                        self.start_scan("Drive scan", paths);
                    }
                }
                let monitor_label = if self.monitor_on {
                    "Real-time: On"
                } else {
                    "Enable Real-time"
                };
                if ui
                    .add_enabled(!self.monitor_on, egui::Button::new(monitor_label))
                    .clicked()
                {
                    self.start_monitor();
                }
            });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Path:");
                ui.add(egui::TextEdit::singleline(&mut self.path_input).desired_width(420.0));
                let go = ui.add_enabled(!self.scan_running, egui::Button::new("Scan Path"));
                if go.clicked() {
                    let p = PathBuf::from(self.path_input.trim());
                    if p.exists() {
                        self.start_scan("Custom scan", vec![p]);
                    } else {
                        self.status = format!("Path not found: {}", self.path_input);
                    }
                }
            });

            ui.add_space(8.0);
            ui.label(RichText::new(&self.status).strong());
            if self.scan_running {
                let frac = if self.progress.files_total > 0 {
                    self.progress.files_scanned as f32 / self.progress.files_total as f32
                } else {
                    0.0
                };
                ui.add(egui::ProgressBar::new(frac).show_percentage());
                if let Some(p) = &self.progress.current_path {
                    ui.label(RichText::new(p.to_string_lossy()).color(MUTED).small());
                }
            }

            ui.separator();
            ui.heading("Detections");
            let threats: Vec<&ScanResult> = self.results.iter().filter(|r| r.is_threat()).collect();
            if threats.is_empty() {
                ui.label(RichText::new("No threats found.").color(GREEN));
            } else {
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .id_salt("detections")
                    .show(ui, |ui| {
                        for r in &threats {
                            let color = match r.verdict {
                                Verdict::Malicious => RED,
                                Verdict::Suspicious => AMBER,
                                Verdict::Clean => GREEN,
                            };
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(r.verdict.name()).color(color).strong());
                                    ui.label(
                                        RichText::new(format!("{:.0}%", r.confidence * 100.0))
                                            .color(MUTED),
                                    );
                                    ui.label(r.file_path.to_string_lossy());
                                });
                                for h in &r.hits {
                                    ui.label(
                                        RichText::new(format!("- {}", h.reason))
                                            .color(MUTED)
                                            .small(),
                                    );
                                }
                            });
                        }
                    });
            }

            ui.separator();
            ui.horizontal(|ui| {
                ui.heading("Quarantine");
                if ui.button("Refresh").clicked() {
                    self.refresh_quarantine();
                }
            });
            if self.quarantine.is_empty() {
                ui.label(RichText::new("Quarantine is empty.").color(MUTED));
            } else {
                egui::ScrollArea::vertical()
                    .max_height(140.0)
                    .id_salt("quarantine")
                    .show(ui, |ui| {
                        let mut action: Option<(Uuid, bool)> = None;
                        for row in &self.quarantine {
                            ui.horizontal(|ui| {
                                ui.label(&row.original_path);
                                ui.label(RichText::new(&row.reason).color(MUTED).small());
                                ui.label(RichText::new(&row.quarantined_at).color(MUTED).small());
                                if ui.button("Restore").clicked() {
                                    action = Some((row.id, false));
                                }
                                if ui.button("Delete").clicked() {
                                    action = Some((row.id, true));
                                }
                            });
                        }
                        if let Some((id, delete)) = action {
                            if let Ok(qm) = QuarantineManager::open_default() {
                                let res = if delete {
                                    qm.delete(id)
                                } else {
                                    qm.restore(id)
                                };
                                self.status = match res {
                                    Ok(()) => "Quarantine updated.".to_string(),
                                    Err(e) => format!("Error: {e}"),
                                };
                            }
                            self.refresh_quarantine();
                        }
                    });
            }

            ui.separator();
            ui.horizontal(|ui| {
                ui.heading("History");
                if ui
                    .selectable_label(self.history_threats_only, "Threats")
                    .clicked()
                {
                    self.history_threats_only = true;
                    self.refresh_history();
                }
                if ui
                    .selectable_label(!self.history_threats_only, "All")
                    .clicked()
                {
                    self.history_threats_only = false;
                    self.refresh_history();
                }
            });
            if self.history.is_empty() {
                ui.label(RichText::new("No history recorded yet.").color(MUTED));
            } else {
                egui::ScrollArea::vertical()
                    .max_height(160.0)
                    .id_salt("history")
                    .show(ui, |ui| {
                        for r in &self.history {
                            let color = if r.verdict == "Malicious" {
                                RED
                            } else if r.verdict == "Suspicious" {
                                AMBER
                            } else {
                                GREEN
                            };
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&r.verdict).color(color));
                                ui.label(&r.file_path);
                                ui.label(RichText::new(&r.scanned_at).color(MUTED).small());
                            });
                        }
                    });
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    auraav_core::crash::install_panic_hook();
    std::thread::spawn(|| {
        let _ = auraav_core::crash::flush_pending();
        if std::env::var_os("AURAAV_NO_UPDATE").is_none() {
            if let Ok(rel) = auraav_core::update::latest_release() {
                if auraav_core::update::is_newer(&rel.version(), env!("CARGO_PKG_VERSION")) {
                    let _ = auraav_core::update::apply_data(&rel);
                }
            }
        }
    });
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 760.0])
            .with_min_inner_size([720.0, 520.0])
            .with_title("auraAV - Unified Antivirus"),
        ..Default::default()
    };
    eframe::run_native("auraAV", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
