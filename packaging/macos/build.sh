#!/usr/bin/env bash
# Build auraAV macOS artifacts (.pkg and .dmg).
#
# This MUST run on macOS: producing a .pkg/.dmg requires Apple's pkgbuild /
# productbuild / hdiutil, which do not exist on Linux. In CI this runs on a
# macos-latest runner (see .github/workflows/release.yml).
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "ERROR: macOS artifacts can only be built on macOS (uname=$(uname -s))." >&2
  exit 1
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
ver="$(sed -nE 's/^version *= *"([^"]+)".*/\1/p' "$root/crates/auraav-cli/Cargo.toml" | head -1)"
dist="$root/dist/macos"
rm -rf "$dist"
mkdir -p "$dist"

echo ">> auraAV $ver (macOS)"
( cd "$root" && cargo build --release -p auraav-cli )
bin="$root/target/release/auraav-cli"

stage="$dist/root"
mkdir -p "$stage/usr/local/bin" "$stage/usr/local/share/auraav"
install -m755 "$bin" "$stage/usr/local/bin/auraav"
cp -R "$root/data" "$stage/usr/local/share/auraav/data"

# --- .pkg -------------------------------------------------------------------
pkgbuild --root "$stage" \
  --identifier "com.auraav.cli" \
  --version "$ver" \
  --install-location "/" \
  "$dist/auraav-${ver}-macos.pkg"
echo "   pkg    : dist/macos/auraav-${ver}-macos.pkg"

# --- .dmg (pkg + installer notes) ------------------------------------------
dmg_src="$dist/dmg"
mkdir -p "$dmg_src"
cp "$dist/auraav-${ver}-macos.pkg" "$dmg_src/"
cp "$here/install-macos.command" "$dmg_src/"
chmod +x "$dmg_src/install-macos.command"
ln -s /Applications "$dmg_src/Applications" 2>/dev/null || true
hdiutil create -volname "auraAV ${ver}" -srcfolder "$dmg_src" \
  -ov -format UDZO "$dist/auraav-${ver}-macos.dmg"
echo "   dmg    : dist/macos/auraav-${ver}-macos.dmg"

echo ">> done: $dist"
