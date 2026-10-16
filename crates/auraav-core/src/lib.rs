// auraAV — Core scanning engine
// Copyright (c) 2026 Shreyasrasuri (shreyastouih-ctrl). All Rights Reserved.
// Proprietary and confidential. See LICENSE and NOTICE. Do not copy or reuse.

pub mod cloud;
pub mod common;
pub mod crash;
pub mod db;
pub mod detection;
pub mod engine;
pub mod filetype;
pub mod fs;
pub mod quarantine;
pub mod signatures;
pub mod types;
pub mod update;

pub use detection::Detector;
pub use engine::{ScanEngine, ScanProgress};
pub use filetype::{FileKind, ScriptKind};
pub use types::*;
