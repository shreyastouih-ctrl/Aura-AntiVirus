#!/usr/bin/env bash
# Build auraAV Linux artifacts: portable .tar.gz, .deb and .rpm.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
assets="$root/packaging/assets"
ver="$(sed -nE 's/^version *= *"([^"]+)".*/\1/p' "$root/crates/auraav-cli/Cargo.toml" | head -1)"
arch="amd64"
dist="$root/dist/linux"
rm -rf "$dist"
mkdir -p "$dist"

echo ">> auraAV $ver (linux/$arch)"

# --- build the binaries -----------------------------------------------------
( cd "$root" && cargo build --release -p auraav-cli -p auraav-gui )
cli="$root/target/release/auraav-cli"
gui="$root/target/release/auraav-gui"
[ -x "$cli" ] || { echo "binary not found: $cli" >&2; exit 1; }
[ -x "$gui" ] || { echo "binary not found: $gui" >&2; exit 1; }

# --- .tar.gz (portable bundle) ---------------------------------------------
bundle="$dist/auraav-${ver}-linux-x86_64"
mkdir -p "$bundle/bin" "$bundle/share/auraav" \
         "$bundle/share/applications" "$bundle/share/icons/hicolor/scalable/apps"
install -m755 "$cli" "$bundle/bin/auraav"
install -m755 "$gui" "$bundle/bin/auraav-gui"
cp -a "$root/data" "$bundle/share/auraav/data"
install -m644 "$assets/auraav.desktop" "$bundle/share/applications/auraav.desktop"
install -m644 "$assets/auraav.svg" "$bundle/share/icons/hicolor/scalable/apps/auraav.svg"
install -m755 "$here/install.sh" "$bundle/install.sh"
tar -C "$dist" -czf "$dist/auraav-${ver}-linux-${arch}.tar.gz" "$(basename "$bundle")"
echo "   tar.gz : dist/linux/auraav-${ver}-linux-${arch}.tar.gz"

# --- staging tree for .deb / .rpm ------------------------------------------
stage="$dist/stage"
mkdir -p "$stage/usr/bin" "$stage/usr/share/auraav" \
         "$stage/usr/share/applications" "$stage/usr/share/icons/hicolor/scalable/apps"
install -m755 "$cli" "$stage/usr/bin/auraav"
install -m755 "$gui" "$stage/usr/bin/auraav-gui"
cp -a "$root/data" "$stage/usr/share/auraav/data"
install -m644 "$assets/auraav.desktop" "$stage/usr/share/applications/auraav.desktop"
install -m644 "$assets/auraav.svg" "$stage/usr/share/icons/hicolor/scalable/apps/auraav.svg"

# --- .deb -------------------------------------------------------------------
if command -v dpkg-deb >/dev/null; then
  deb="$dist/auraav_${ver}_${arch}"
  mkdir -p "$deb/DEBIAN"
  cp -a "$stage/usr" "$deb/"
  cat > "$deb/DEBIAN/control" <<EOF
Package: auraav
Version: ${ver}
Architecture: ${arch}
Maintainer: Shreyasrasuri <shreyastouih@protonmail.com>
Section: utils
Priority: optional
Homepage: https://github.com/shreyastouih-ctrl/Aura-AntiVirus
Depends: libgtk-3-0, libwebkit2gtk-4.1-0 | libxkbcommon0
Description: auraAV - offline-first, no-subscription antivirus
 Unified static/heuristic/similarity detection engine with a GUI and a CLI.
EOF
  cat > "$deb/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
command -v update-desktop-database >/dev/null && update-desktop-database -q || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
echo "auraAV installed. Run the GUI: auraav-gui   or the CLI: auraav --help"
EOF
  chmod 755 "$deb/DEBIAN/postinst"
  dpkg-deb --build --root-owner-group "$deb" "$dist/auraav_${ver}_${arch}.deb" >/dev/null
  echo "   deb    : dist/linux/auraav_${ver}_${arch}.deb"
fi

# --- .rpm -------------------------------------------------------------------
if command -v rpmbuild >/dev/null; then
  top="$dist/rpmbuild"
  mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
  cat > "$top/SPECS/auraav.spec" <<EOF
Name:           auraav
Version:        ${ver}
Release:        1
Summary:        Offline-first, no-subscription antivirus
License:        GPL-3.0-only
BuildArch:      x86_64
AutoReqProv:    no

%description
auraAV is a unified static/heuristic/similarity detection engine with a GUI and a CLI.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/share/auraav/data \\
         %{buildroot}/usr/share/applications %{buildroot}/usr/share/icons/hicolor/scalable/apps
install -m755 "$cli" %{buildroot}/usr/bin/auraav
install -m755 "$gui" %{buildroot}/usr/bin/auraav-gui
cp -a "$root/data/." %{buildroot}/usr/share/auraav/data/
install -m644 "$assets/auraav.desktop" %{buildroot}/usr/share/applications/auraav.desktop
install -m644 "$assets/auraav.svg" %{buildroot}/usr/share/icons/hicolor/scalable/apps/auraav.svg

%files
/usr/bin/auraav
/usr/bin/auraav-gui
/usr/share/auraav/data
/usr/share/applications/auraav.desktop
/usr/share/icons/hicolor/scalable/apps/auraav.svg
EOF
  rpmbuild -bb --define "_topdir $top" "$top/SPECS/auraav.spec" >/dev/null 2>&1
  find "$top/RPMS" -name '*.rpm' -exec cp {} "$dist/" \;
  echo "   rpm    : $(ls "$dist"/*.rpm 2>/dev/null | xargs -n1 basename 2>/dev/null)"
fi

echo ">> done: $dist"
