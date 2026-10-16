#!/usr/bin/env bash
# Build auraAV Windows artifacts: portable .zip and an .msi installer.
# Cross-compiles from Linux with mingw-w64; the .msi is built with wixl.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
ver="$(sed -nE 's/^version *= *"([^"]+)".*/\1/p' "$root/crates/auraav-cli/Cargo.toml" | head -1)"
dist="$root/dist/windows"
rm -rf "$dist"
mkdir -p "$dist"

target="x86_64-pc-windows-gnu"
echo ">> auraAV $ver (windows x64, $target)"

rustup target add "$target" >/dev/null 2>&1 || true
( cd "$root" && cargo build --release --target "$target" -p auraav-cli )
exe="$root/target/$target/release/auraav-cli.exe"
[ -f "$exe" ] || { echo "exe not found: $exe" >&2; exit 1; }

# --- portable zip -----------------------------------------------------------
stage="$dist/auraav-${ver}-win64"
mkdir -p "$stage"
cp "$exe" "$stage/auraav.exe"
cp -a "$root/data" "$stage/data"
cat > "$stage/README.txt" <<EOF
auraAV ${ver} (Windows x64)
Run:  auraav.exe --help
Data (signatures/rules) lives in the data\ subdirectory next to this exe.
EOF
if command -v bsdtar >/dev/null; then
  ( cd "$dist" && bsdtar -a -cf "auraav-${ver}-win64.zip" "$(basename "$stage")" )
elif command -v zip >/dev/null; then
  ( cd "$dist" && zip -qr "auraav-${ver}-win64.zip" "$(basename "$stage")" )
else
  echo "no zip tool available" >&2; exit 1
fi
echo "   zip    : dist/windows/auraav-${ver}-win64.zip"

# --- .msi via wixl ----------------------------------------------------------
if command -v wixl >/dev/null; then
  guid_for() { # deterministic GUID from an arbitrary string
    local h; h="$(printf '%s' "$1" | md5sum | cut -c1-32)"
    printf '%s-%s-%s-%s-%s' "${h:0:8}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:12}"
  }
  upgrade_guid="$(guid_for "auraav-upgrade-code")"

  wxs="$dist/auraav.wxs"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">'
    echo "  <Product Id=\"*\" Name=\"auraAV\" Language=\"1033\" Version=\"${ver}\""
    echo "           Manufacturer=\"auraAV\" UpgradeCode=\"${upgrade_guid}\">"
    echo '    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" Platform="x64"/>'
    echo '    <MajorUpgrade DowngradeErrorMessage="A newer version of auraAV is already installed."/>'
    echo '    <MediaTemplate EmbedCab="yes"/>'
    echo '    <Directory Id="TARGETDIR" Name="SourceDir">'
    echo '      <Directory Id="ProgramFiles64Folder">'
    echo '        <Directory Id="INSTALLDIR" Name="auraAV">'
    echo "          <Component Id=\"MainExe\" Guid=\"$(guid_for "auraav.exe")\" Win64=\"yes\">"
    echo "            <File Id=\"auraav.exe\" Source=\"${stage}/auraav.exe\" KeyPath=\"yes\"/>"
    echo '            <Environment Id="PATH" Name="PATH" Value="[INSTALLDIR]" Part="last" Action="set" System="yes"/>'
    echo '          </Component>'
    # data files, preserved as INSTALLDIR/data/<sub>/<file>
    while IFS= read -r f; do
      rel="${f#"$root/data/"}"          # e.g. rules/example_rules.yar
      echo "          <Directory Id=\"D_$(guid_for "$rel")\" Name=\"$(dirname "$rel")\">"
      echo "            <Component Id=\"C_$(guid_for "$rel")\" Guid=\"$(guid_for "$rel")\" Win64=\"yes\">"
      echo "              <File Id=\"F_$(guid_for "$rel")\" Source=\"${f}\"/>"
      echo '            </Component>'
      echo '          </Directory>'
    done < <(find "$root/data" -type f | sort)
    echo '        </Directory>'
    echo '      </Directory>'
    echo '    </Directory>'
    echo '    <Feature Id="Main" Title="auraAV" Level="1">'
    echo '      <ComponentRef Id="MainExe"/>'
    while IFS= read -r f; do
      rel="${f#"$root/data/"}"
      echo "      <ComponentRef Id=\"C_$(guid_for "$rel")\"/>"
    done < <(find "$root/data" -type f | sort)
    echo '    </Feature>'
    echo '  </Product>'
    echo '</Wix>'
  } > "$wxs"

  wixl -a x64 -o "$dist/auraav-${ver}-win64.msi" "$wxs"
  echo "   msi    : dist/windows/auraav-${ver}-win64.msi"
fi

echo ">> done: $dist"
