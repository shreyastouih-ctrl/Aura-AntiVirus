use std::path::PathBuf;
use std::time::Duration;

use auraav_core::db::Db;
use auraav_core::quarantine::QuarantineManager;
use auraav_core::types::{HeuristicSensitivity, SimilaritySensitivity};
use auraav_core::{ScanConfig, ScanEngine, Verdict};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "auraav")]
#[command(version, about = "auraAV - unified, offline-first antivirus (no subscription)")]
struct Cli {
    /// Only report threats that are Malicious (skip Suspicious).
    #[arg(long, global = true)]
    malicious_only: bool,

    /// Heuristic aggressiveness: off | low | medium | high.
    #[arg(long, global = true, default_value = "low")]
    sensitivity: String,

    /// Do not write results to the scan-history database.
    #[arg(long, global = true)]
    no_history: bool,

    /// Emit machine-readable JSON results instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    /// Print every scanned file, not just detected threats.
    #[arg(long, global = true)]
    all: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Quick scan of common user paths.
    #[command(name = "quick-scan")]
    QuickScan {
        /// Paths to scan (defaults to common user dirs).
        paths: Vec<PathBuf>,
    },
    /// Full scan of the filesystem (defaults to /).
    #[command(name = "full-scan")]
    FullScan {
        paths: Vec<PathBuf>,
    },
    /// Scan specific paths.
    Scan {
        paths: Vec<PathBuf>,
        /// Move detected files into quarantine.
        #[arg(long)]
        quarantine: bool,
    },
    /// Scan all currently-mounted removable/external drives.
    #[command(name = "scan-drives")]
    ScanDrives {
        #[arg(long)]
        quarantine: bool,
    },
    /// Watch common directories and scan files as they are written.
    Monitor {
        paths: Vec<PathBuf>,
    },
    /// Manage the quarantine.
    #[command(subcommand)]
    Quarantine(QuarantineCmd),
    /// Show recent scan history.
    History {
        #[arg(long, default_value_t = 40)]
        limit: usize,
        /// Only show threats (non-clean results).
        #[arg(long)]
        threats_only: bool,
    },
    /// List mounted drives.
    Drives,
    /// Manage run-at-startup integration.
    Startup {
        #[command(subcommand)]
        action: StartupCmd,
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// List quarantined files.
    List,
    /// Restore a file to its original location.
    Restore { id: String },
    /// Permanently delete a quarantined file.
    Delete { id: String },
}

#[derive(Subcommand)]
enum StartupCmd {
    Install,
    Uninstall,
    Status,
}

fn build_config(cli: &Cli) -> ScanConfig {
    let mut config = ScanConfig::default();
    config.heuristic_sensitivity = match cli.sensitivity.to_ascii_lowercase().as_str() {
        "off" => HeuristicSensitivity::Off,
        "medium" => HeuristicSensitivity::Medium,
        "high" => HeuristicSensitivity::High,
        _ => HeuristicSensitivity::Low,
    };
    config.similarity_sensitivity = SimilaritySensitivity::default();
    config
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let config = build_config(&cli);
    let is_threat = |v: Verdict| {
        if cli.malicious_only {
            matches!(v, Verdict::Malicious)
        } else {
            !matches!(v, Verdict::Clean)
        }
    };

    match cli.command {
        Commands::QuickScan { mut paths } => {
            if paths.is_empty() {
                paths = default_quick_paths();
            }
            run_scan(&config, &paths, false, is_threat, cli.no_history, cli.all, cli.json)?;
        }
        Commands::FullScan { paths } => {
            let paths = if paths.is_empty() {
                vec![PathBuf::from("/")]
            } else {
                paths
            };
            run_scan(&config, &paths, false, is_threat, cli.no_history, cli.all, cli.json)?;
        }
        Commands::Scan { paths, quarantine } => {
            if paths.is_empty() {
                anyhow::bail!("no paths specified");
            }
            run_scan(&config, &paths, quarantine, is_threat, cli.no_history, cli.all, cli.json)?;
        }
        Commands::ScanDrives { quarantine } => {
            let drives = auraav_platform::list_removable_drives();
            if drives.is_empty() {
                println!("No removable drives detected.");
                return Ok(());
            }
            let paths: Vec<PathBuf> = drives.iter().map(|d| d.mount_point.clone()).collect();
            for d in &drives {
                println!("Scanning removable drive {} ({})", d.mount_point.display(), d.name);
            }
            run_scan(&config, &paths, quarantine, is_threat, cli.no_history, cli.all, cli.json)?;
        }
        Commands::Monitor { paths } => {
            let paths = if paths.is_empty() {
                auraav_platform::default_watch_paths()
            } else {
                paths
            };
            let db = auraav_core::signatures::load_default_db();
            let detector = auraav_core::Detector::new(db, config);
            println!(
                "Real-time protection active on {} path(s):",
                paths.len()
            );
            for p in &paths {
                println!("  {}", p.display());
            }
            auraav_platform::watch(detector, paths, Duration::from_millis(500), |event| {
                println!(
                    "[{}] {} — {}",
                    event.verdict.name(),
                    event.path.display(),
                    event.summary
                );
            })
            .map_err(|e| anyhow::anyhow!("monitor failed: {e}"))?;
        }
        Commands::Quarantine(cmd) => {
            let qm = QuarantineManager::open_default()?;
            match cmd {
                QuarantineCmd::List => {
                    let entries = qm.list()?;
                    if entries.is_empty() {
                        println!("Quarantine is empty.");
                    }
                    for e in entries {
                        println!(
                            "{}  {}\n      {}  (confidence {:.0}%)",
                            e.id,
                            e.original_path.display(),
                            e.reason,
                            e.confidence * 100.0
                        );
                    }
                }
                QuarantineCmd::Restore { id } => {
                    qm.restore(uuid::Uuid::parse_str(&id)?)?;
                    println!("Restored {id}");
                }
                QuarantineCmd::Delete { id } => {
                    qm.delete(uuid::Uuid::parse_str(&id)?)?;
                    println!("Deleted {id}");
                }
            }
        }
        Commands::History {
            limit,
            threats_only,
        } => {
            let db = Db::open(Db::default_path())?;
            let rows = if threats_only {
                db.recent_threats(limit)?
            } else {
                db.recent_results(limit)?
            };
            if rows.is_empty() {
                println!("No history recorded yet.");
            }
            for r in rows {
                println!(
                    "{:<20} {:<10} {:>5.1}%  {}",
                    &r.scanned_at[..r.scanned_at.len().min(19)],
                    r.verdict,
                    r.confidence * 100.0,
                    r.file_path.display()
                );
            }
        }
        Commands::Drives => {
            let drives = auraav_platform::list_drives();
            for d in &drives {
                let size = match (d.total_bytes, d.available_bytes) {
                    (Some(t), Some(a)) => format!(
                        "{:.1}G free / {:.1}G",
                        a as f64 / 1e9,
                        t as f64 / 1e9
                    ),
                    _ => String::from("?"),
                };
                println!(
                    "{:<14} {:<8} {:<24} {}",
                    d.mount_point.display(),
                    format!("{:?}", d.kind),
                    d.name,
                    size
                );
            }
        }
        Commands::Startup { action } => {
            let bin = std::env::current_exe()?;
            match action {
                StartupCmd::Install => {
                    auraav_platform::install_startup(&bin)?;
                    println!("Startup integration installed.");
                }
                StartupCmd::Uninstall => {
                    auraav_platform::uninstall_startup()?;
                    println!("Startup integration removed.");
                }
                StartupCmd::Status => {
                    println!(
                        "Startup integration: {}",
                        if auraav_platform::is_startup_installed() {
                            "installed"
                        } else {
                            "not installed"
                        }
                    );
                }
            }
        }
    }
    Ok(())
}

fn default_quick_paths() -> Vec<PathBuf> {
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
    paths
}

fn run_scan<F: Fn(Verdict) -> bool>(
    config: &ScanConfig,
    paths: &[PathBuf],
    quarantine: bool,
    is_threat: F,
    no_history: bool,
    show_all: bool,
    json: bool,
) -> anyhow::Result<()> {
    let engine = ScanEngine::new(config.clone());
    let results = engine.scan_paths(paths, None);
    let threats: Vec<_> = results.iter().filter(|r| is_threat(r.verdict)).collect();

    if json {
        let shown: Vec<_> = if show_all {
            results.iter().collect()
        } else {
            threats.clone()
        };
        println!("{}", serde_json::to_string(&shown)?);
    } else {
        println!(
            "Scanned {} files, {} threat(s) found.",
            results.len(),
            threats.len()
        );

        let listed: Vec<_> = if show_all {
            results.iter().collect()
        } else {
            threats.clone()
        };
        for t in &listed {
            println!(
                "  [{}] {:.0}%  {}",
                t.verdict.name(),
                t.confidence * 100.0,
                t.file_path.display()
            );
            for hit in &t.hits {
                println!("      - {:?}: {}", hit.layer, hit.reason);
            }
        }
    }

    if quarantine && !threats.is_empty() {
        let qm = QuarantineManager::open_default()?;
        for t in &threats {
            if t.verdict == Verdict::Malicious {
                match qm.quarantine(t, t.hits.first().map(|h| h.reason.as_str()).unwrap_or("detected")) {
                    Ok(entry) => println!("  quarantined {} -> {}", t.file_path.display(), entry.id),
                    Err(e) => eprintln!("  failed to quarantine {}: {e}", t.file_path.display()),
                }
            }
        }
    }

    if !no_history {
        if let Ok(db) = Db::open(Db::default_path()) {
            for r in &results {
                let _ = db.save_result(r);
            }
        }
    }
    Ok(())
}
