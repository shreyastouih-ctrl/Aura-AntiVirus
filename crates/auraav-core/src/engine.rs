use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crossbeam_channel::Sender;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::detection::Detector;
use crate::signatures::{load_default_db, SignatureDb};
use crate::types::{ScanConfig, ScanResult};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanProgress {
    pub files_scanned: usize,
    pub files_total: usize,
    pub current_path: Option<PathBuf>,
    pub threats_found: usize,
    pub done: bool,
}

/// High-level scanning driver: walks paths and runs the [`Detector`] over every
/// file in parallel, reporting progress and aggregating results.
pub struct ScanEngine {
    detector: Arc<Detector>,
    config: ScanConfig,
}

impl ScanEngine {
    pub fn new(config: ScanConfig) -> Self {
        Self::with_db(config, load_default_db())
    }

    pub fn with_db(config: ScanConfig, db: SignatureDb) -> Self {
        let detector = Arc::new(Detector::new(db, config.clone()));
        Self { detector, config }
    }

    pub fn detector(&self) -> Arc<Detector> {
        Arc::clone(&self.detector)
    }

    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Scan a set of paths, returning a result for every readable file.
    pub fn scan_paths(
        &self,
        paths: &[PathBuf],
        progress_tx: Option<Sender<ScanProgress>>,
    ) -> Vec<ScanResult> {
        let start = Instant::now();
        let files = crate::fs::scan_paths(paths, &self.config);
        let total = files.len();

        let progress = Arc::new(Mutex::new(ScanProgress {
            files_scanned: 0,
            files_total: total,
            current_path: None,
            threats_found: 0,
            done: false,
        }));

        let results: Vec<ScanResult> = files
            .par_iter()
            .filter_map(|f| {
                let result = self.detector.scan_file(&f.path);
                if let Some(ref tx) = progress_tx {
                    if let Ok(mut p) = progress.lock() {
                        p.files_scanned += 1;
                        p.current_path = Some(f.path.clone());
                        if let Some(r) = &result {
                            if r.is_threat() {
                                p.threats_found += 1;
                            }
                        }
                        let _ = tx.send(p.clone());
                    }
                }
                result
            })
            .collect();

        let threats = results.iter().filter(|r| r.is_threat()).count();
        tracing::info!(
            "scan finished in {:?}: {} files scanned, {} threats",
            start.elapsed(),
            results.len(),
            threats
        );
        if let Some(tx) = progress_tx {
            if let Ok(mut p) = progress.lock() {
                p.done = true;
                p.current_path = None;
                let _ = tx.send(p.clone());
            }
        }
        results
    }

    /// Scan a set of paths and only return the threats (convenience helper).
    pub fn scan_for_threats(&self, paths: &[PathBuf]) -> Vec<ScanResult> {
        self.scan_paths(paths, None)
            .into_iter()
            .filter(|r| r.is_threat())
            .collect()
    }
}
