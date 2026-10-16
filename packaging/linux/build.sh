#!/usr/bin/env bash
# Build auraAV Linux artifacts: portable .tar.gz, .deb and .rpm.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
ver="$(sed -nE 's/^version *= *"([^"]+)".*/\1/p' "$root/crates/auraav-cli/Cargo.toml" | head -1)"
arch="amd64"
dist="$root/dist/linux"
rm -rf "$dist"
mkdir -p "$dist"

echo ">> auraAV $ver (linux/$arch)"

# --- build the binary -------------------------------------------------------
( cd "$root" && cargo build --release -p auraav-cli )
bin="$root/target/release/auraav-cli"
[ -x "$bin" ] || { echo "binary not found: $bin" >&2; exit 1; }

# --- .tar.gz (portable bundle) ---------------------------------------------
bundle="$dist/auraav-${ver}-linux-x86_64"
mkdir -p "$bundle/bin" "$bundle/share/auraav"
install -m755 "$bin" "$bundle/bin/auraav"
cp -a "$root/data" "$bundle/share/auraav/data"
install -m755 "$here/install.sh" "$bundle/install.sh"
tar -C "$dist" -czf "$dist/auraav-${ver}-linux-${arch}.tar.gz" "$(basename "$bundle")"
echo "   tar.gz : dist/linux/auraav-${ver}-linux-${arch}.tar.gz"

# --- staging tree for .deb / .rpm ------------------------------------------
stage="$dist/stage"
mkdir -p "$stage/usr/bin" "$stage/usr/share/auraav"
install -m755 "$bin" "$stage/usr/bin/auraav"
cp -a "$root/data" "$stage/usr/share/auraav/data"

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
Homepage: https://github.com/Shreyasrasuri/auraav
Description: auraAV - offline-first, no-subscription antivirus
 Unified static/heuristic/similarity detection engine with a CLI.
EOF
  cat > "$deb/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
echo "auraAV installed. Run: auraav --help"
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
auraAV is a unified static/heuristic/similarity detection engine with a CLI.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/share/auraav/data
install -m755 "$bin" %{buildroot}/usr/bin/auraav
cp -a "$root/data/." %{buildroot}/usr/share/auraav/data/

%files
/usr/bin/auraav
/usr/share/auraav/data
EOF
  rpmbuild -bb --define "_topdir $top" "$top/SPECS/auraav.spec" >/dev/null 2>&1
  find "$top/RPMS" -name '*.rpm' -exec cp {} "$dist/" \;
  echo "   rpm    : $(basename "$(find "$dist" -maxdepth 1 -name '*.rpm' | head -1)")"
fi

echo ">> done: $dist"
