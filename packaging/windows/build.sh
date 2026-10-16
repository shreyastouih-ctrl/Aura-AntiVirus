#!/usr/bin/env bash
# Build auraAV Windows artifacts: portable .zip and .msi (GUI + CLI).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
assets="$root/packaging/assets"
ver="$(sed -nE 's/^version *= *"([^"]+)".*/\1/p' "$root/crates/auraav-cli/Cargo.toml" | head -1)"
dist="$root/dist/windows"
rm -rf "$dist"
mkdir -p "$dist"

echo ">> auraAV $ver (windows/x64)"

# --- build the binaries (GUI + CLI) ----------------------------------------
( cd "$root" && cargo build --release --target x86_64-pc-windows-gnu -p auraav-cli -p auraav-gui )
cli="$root/target/x86_64-pc-windows-gnu/release/auraav-cli.exe"
gui="$root/target/x86_64-pc-windows-gnu/release/auraav-gui.exe"
[ -f "$cli" ] || { echo "exe not found: $cli" >&2; exit 1; }
[ -f "$gui" ] || { echo "exe not found: $gui" >&2; exit 1; }

# --- portable zip -----------------------------------------------------------
stage="$dist/auraav-${ver}-win64"
mkdir -p "$stage"
cp "$cli" "$stage/auraav.exe"
cp "$gui" "$stage/auraav-gui.exe"
cp "$assets/auraav.ico" "$stage/auraav.ico"
cp -a "$root/data" "$stage/data"
cat > "$stage/README.txt" <<EOF
auraAV ${ver} (Windows x64)
GUI : double-click auraav-gui.exe (or the Start Menu shortcut after installing the .msi)
CLI : auraav.exe --help
Data: signatures/rules live in the data\ subdirectory next to these exes.
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
  guid_for() { local h; h="$(printf '%s' "$1" | md5sum | cut -c1-32)"
    printf '%s-%s-%s-%s-%s' "${h:0:8}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:12}"; }
  san() { printf '%s' "$1" | tr -c 'A-Za-z0-9' '_'; }
  upgrade_guid="$(guid_for "auraav-upgrade-code")"

  wxs="$dist/auraav.wxs"
  {
    echo '<?xml version="1.0" encoding="UTF-8"?>'
    echo '<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">'
    echo "  <Product Id=\"*\" Name=\"auraAV\" Language=\"1033\" Version=\"${ver}\""
    echo "           Manufacturer=\"auraAV\" UpgradeCode=\"${upgrade_guid}\">"
    echo '    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine"/>'
    echo '    <MajorUpgrade DowngradeErrorMessage="A newer version of auraAV is already installed."/>'
    echo '    <Media Id="1" Cabinet="auraav.cab" EmbedCab="yes"/>'
    echo '    <Directory Id="TARGETDIR" Name="SourceDir">'
    echo '      <Directory Id="ProgramFiles64Folder">'
    echo '        <Directory Id="INSTALLDIR" Name="auraAV">'
    echo "          <Component Id=\"MainExe\" Guid=\"$(guid_for "auraav.exe")\">"
    echo "            <File Id=\"auraav.exe\" Source=\"${stage}/auraav.exe\" KeyPath=\"yes\"/>"
    echo '          </Component>'
    echo "          <Component Id=\"GuiExe\" Guid=\"$(guid_for "auraav-gui.exe")\">"
    echo "            <File Id=\"auraav-gui.exe\" Source=\"${stage}/auraav-gui.exe\" KeyPath=\"yes\"/>"
    echo '          </Component>'
    echo "          <Component Id=\"AppIcon\" Guid=\"$(guid_for "auraav.ico")\">"
    echo "            <File Id=\"auraav.ico\" Source=\"${stage}/auraav.ico\" KeyPath=\"yes\"/>"
    echo '          </Component>'
    while IFS= read -r d; do
      name="$(basename "$d")"
      echo "          <Directory Id=\"D_$(san "$name")\" Name=\"${name}\">"
      while IFS= read -r f; do
        rel="${f#"$root/data/"}"
        echo "            <Component Id=\"Comp_$(san "$rel")\" Guid=\"$(guid_for "$rel")\">"
        echo "              <File Id=\"File_$(san "$rel")\" Source=\"${f}\"/>"
        echo '            </Component>'
      done < <(find "$d" -maxdepth 1 -type f | sort)
      echo '          </Directory>'
    done < <(find "$root/data" -mindepth 1 -maxdepth 1 -type d | sort)
    echo '        </Directory>'
    echo '      </Directory>'
    # Start Menu shortcut -> the GUI executable
    echo '      <Directory Id="ProgramMenuFolder">'
    echo '        <Directory Id="AppMenuFolder" Name="auraAV">'
    echo "          <Component Id=\"AppShortcut\" Guid=\"$(guid_for "auraav-shortcut")\">"
    echo '            <Shortcut Id="StartMenuShortcut" Name="auraAV"'
    echo '                      Description="auraAV antivirus"'
    echo '                      Target="[INSTALLDIR]auraav-gui.exe" WorkingDirectory="INSTALLDIR"/>'
    echo '            <RemoveFolder Id="AppMenuFolder" On="uninstall"/>'
    echo '            <RegistryValue Root="HKCU" Key="Software\auraAV" Name="installed"'
    echo '                           Type="integer" Value="1" KeyPath="yes"/>'
    echo '          </Component>'
    echo '        </Directory>'
    echo '      </Directory>'
    echo '    </Directory>'
    echo '    <Feature Id="Main" Title="auraAV" Level="1">'
    echo '      <ComponentRef Id="MainExe"/>'
    echo '      <ComponentRef Id="GuiExe"/>'
    echo '      <ComponentRef Id="AppIcon"/>'
    echo '      <ComponentRef Id="AppShortcut"/>'
    while IFS= read -r f; do
      rel="${f#"$root/data/"}"
      echo "      <ComponentRef Id=\"Comp_$(san "$rel")\"/>"
    done < <(find "$root/data" -type f | sort)
    echo '    </Feature>'
    echo '  </Product>'
    echo '</Wix>'
  } > "$wxs"

  wixl -a x64 -o "$dist/auraav-${ver}-win64.msi" "$wxs"
  echo "   msi    : dist/windows/auraav-${ver}-win64.msi"
else
  echo "ERROR: wixl not found; cannot build the .msi installer" >&2
  exit 1
fi

echo ">> done: $dist"
