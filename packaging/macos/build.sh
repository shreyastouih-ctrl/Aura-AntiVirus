#!/usr/bin/env bash
# Build auraAV macOS artifacts: .pkg, .dmg and a portable .tar.gz (for the
# in-app auto-updater).
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
assets="$root/packaging/assets"
ver="$(sed -nE 's/^version *= *"([^"]+)".*/\1/p' "$root/crates/auraav-cli/Cargo.toml" | head -1)"
dist="$root/dist/macos"
rm -rf "$dist"
mkdir -p "$dist"

echo ">> auraAV $ver (macOS)"

# --- build the binaries -----------------------------------------------------
( cd "$root" && cargo build --release -p auraav-cli -p auraav-gui )
cli="$root/target/release/auraav-cli"
gui="$root/target/release/auraav-gui"
[ -x "$cli" ] || { echo "binary not found: $cli" >&2; exit 1; }
[ -x "$gui" ] || { echo "binary not found: $gui" >&2; exit 1; }

# --- icon: PNG -> .icns -----------------------------------------------------
icns="$dist/auraAV.icns"
png="$assets/auraav.png"
if [ -f "$png" ] && command -v sips >/dev/null && command -v iconutil >/dev/null; then
  iconset="$dist/auraAV.iconset"
  rm -rf "$iconset"
  mkdir -p "$iconset"
  sips -z 16 16     "$png" --out "$iconset/icon_16x16.png"      >/dev/null
  sips -z 32 32     "$png" --out "$iconset/icon_16x16@2x.png"   >/dev/null
  sips -z 32 32     "$png" --out "$iconset/icon_32x32.png"      >/dev/null
  sips -z 64 64     "$png" --out "$iconset/icon_32x32@2x.png"   >/dev/null
  sips -z 128 128   "$png" --out "$iconset/icon_128x128.png"    >/dev/null
  sips -z 256 256   "$png" --out "$iconset/icon_128x128@2x.png" >/dev/null
  sips -z 256 256   "$png" --out "$iconset/icon_256x256.png"    >/dev/null
  sips -z 512 512   "$png" --out "$iconset/icon_256x256@2x.png" >/dev/null
  sips -z 512 512   "$png" --out "$iconset/icon_512x512.png"    >/dev/null
  sips -z 1024 1024 "$png" --out "$iconset/icon_512x512@2x.png" >/dev/null
  iconutil -c icns "$iconset" -o "$icns"
  echo "   icns   : dist/macos/auraAV.icns"
fi

# --- .app bundle ------------------------------------------------------------
app="$dist/auraAV.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
install -m755 "$gui" "$app/Contents/MacOS/auraav-gui"
install -m755 "$cli" "$app/Contents/MacOS/auraav"
[ -f "$icns" ] && install -m644 "$icns" "$app/Contents/Resources/auraAV.icns"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>auraAV</string>
  <key>CFBundleDisplayName</key><string>auraAV</string>
  <key>CFBundleIdentifier</key><string>com.auraav.gui</string>
  <key>CFBundleExecutable</key><string>auraav-gui</string>
  <key>CFBundleIconFile</key><string>auraAV</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${ver}</string>
  <key>CFBundleVersion</key><string>${ver}</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# Ad-hoc signature so the bundle launches locally. Not notarized.
if command -v codesign >/dev/null; then
  codesign --force --deep --sign - "$app" >/dev/null 2>&1 || true
fi

# --- portable .tar.gz (used by the in-app auto-updater) ---------------------
bundle="$dist/auraav-${ver}-macos"
mkdir -p "$bundle/bin" "$bundle/share/auraav"
cp -R "$app" "$bundle/auraAV.app"
install -m755 "$cli" "$bundle/bin/auraav"
install -m755 "$gui" "$bundle/bin/auraav-gui"
cp -a "$root/data" "$bundle/share/auraav/data"
tar -C "$dist" -czf "$dist/auraav-${ver}-macos.tar.gz" "$(basename "$bundle")"
echo "   tar.gz : dist/macos/auraav-${ver}-macos.tar.gz"

# --- .pkg -------------------------------------------------------------------
stage="$dist/pkg-root"
mkdir -p "$stage/usr/local/bin" "$stage/usr/local/share/auraav" "$stage/Applications"
install -m755 "$cli" "$stage/usr/local/bin/auraav"
install -m755 "$gui" "$stage/usr/local/bin/auraav-gui"
cp -a "$root/data" "$stage/usr/local/share/auraav/data"
cp -R "$app" "$stage/Applications/auraAV.app"
pkgbuild --root "$stage" \
  --identifier "com.auraav.pkg" \
  --version "$ver" \
  --install-location "/" \
  "$dist/auraav-${ver}-macos.pkg"
echo "   pkg    : dist/macos/auraav-${ver}-macos.pkg"

# --- .dmg (pkg + installer script + Applications shortcut) ------------------
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
