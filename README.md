# auraAV

auraAV is a unified multi-engine antivirus built to scan **all threat types at once**. It runs multiple detection layers in parallel (signatures, structural analysis, heuristics, similarity hashing, code structure/CFG analysis) and fuses results into a single unified verdict.

**Key Features:**
- **Unified scanning** - All detection methods run simultaneously per file, not sequentially
- **Multi-type coverage** - Designed to detect polymorphic, metamorphic, trojans, worms, droppers, ransomware, file infectors, scripts, packed files, and more in one pass
- **Offline-first** - Core detection works without internet. No subscription, no account, no forced cloud lookups
- **User control** - Quarantine with explicit override to allow genuine files
- **System integration** - Startup quick scan, external drive detection, real-time monitoring (toggleable)
- **Cross-platform** - Linux and Windows (desktop GUI + CLI)
- **Easy UI** - Simple interface with transparent detection reasons

**Detection Layers (all run on every file in one pass):**
L1 Hash • L2 YARA-like rules • L3 Structural (PE/ELF/Mach-O) • L5 Instruction normalization (iced-x86) • L6 Code/CFG similarity • L8 Fuzzy byte similarity (MinHash) • L9 Static heuristics • L10 Behavioral (opt-in)

> A `Malicious` verdict always requires a *definitive* signal (exact hash or strong
> code/fuzzy-similarity match). Heuristic/rule-only evidence can reach `Suspicious`
> but never triggers automatic removal — this keeps false positives on ordinary
> software low.

**Important:** No AV can detect every virus. auraAV is designed with layered, transparent detection and honest limitations.

## Quick Start (CLI)

```bash
source ~/.cargo/env
cd tries/auraav

cargo run -p auraav-cli -- quick-scan
cargo run -p auraav-cli -- full-scan
cargo run -p auraav-cli -- scan <path> [--quarantine]
cargo run -p auraav-cli -- scan-drives [--quarantine]
cargo run -p auraav-cli -- monitor [paths...]        # real-time protection
cargo run -p auraav-cli -- quarantine list
cargo run -p auraav-cli -- quarantine restore <id>
cargo run -p auraav-cli -- quarantine delete <id>
cargo run -p auraav-cli -- history --threats-only
cargo run -p auraav-cli -- drives
cargo run -p auraav-cli -- startup install|uninstall|status
```

Global flags: `--malicious-only`, `--sensitivity off|low|medium|high`, `--no-history`.

## Desktop GUI

`auraav-gui` is a self-contained native app (egui) — no WebKit/GTK runtime
required. Scan, watch real-time protection, browse detections/quarantine/history.

```bash
cargo run -p auraav-gui        # run from source
```

Installers are on the [releases page](https://github.com/shreyastouih-ctrl/Aura-AntiVirus/releases):
Windows `.msi` (Start Menu shortcut) / `.zip`, Linux `.deb` / `.rpm` / `.tar.gz`.

## Build CLI Only

```bash
cd crates/auraav-cli
cargo build --release
```

## Testing

Detection is validated against a safe, synthetic corpus (EICAR plus inert byte
patterns for each layer) covering Linux and macOS samples — no live malware is
used.

Native (Linux, macOS, Windows):

```bash
cargo test -p auraav-core          # includes cross-platform detection tests
```

Full corpus harness (Linux/macOS; requires `jq`):

```bash
cargo build --release -p auraav-cli
AURAAV_BIN=./target/release/auraav-cli \
CORPUS_DIR=/tmp/auraav-corpus \
GENERATE_SH=./docker/corpus/generate.sh \
LOG_FILE=/tmp/auraav-scan.json \
./docker/run-tests.sh
```

Docker (Linux containers; Docker Desktop also runs this on macOS):

```bash
docker build -f docker/Dockerfile -t auraav-test .
docker run --rm auraav-test
```

## License

GPL-3.0-only
# Aura-AntiVirus
