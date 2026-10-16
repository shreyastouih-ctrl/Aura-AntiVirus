#!/usr/bin/env bash
# Portable installer for the auraAV .tar.gz bundle.
#
#   ./install.sh [--prefix /usr/local]
#
# Installs the GUI (auraav-gui), the CLI (auraav), data, desktop entry and icon.
# The binaries discover their data via the executable's location, so any prefix
# works as long as the relative layout (bin/, share/auraav/data/) is kept.
set -euo pipefail

prefix="/usr/local"
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) prefix="$2"; shift 2 ;;
    --prefix=*) prefix="${1#*=}"; shift ;;
    -h|--help) echo "usage: $0 [--prefix DIR]"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -x "$here/bin/auraav" ] || { echo "missing $here/bin/auraav" >&2; exit 1; }

echo "Installing auraAV to $prefix"
install -d "$prefix/bin" "$prefix/share/auraav" \
           "$prefix/share/applications" "$prefix/share/icons/hicolor/scalable/apps"
install -m755 "$here/bin/auraav" "$prefix/bin/auraav"
[ -x "$here/bin/auraav-gui" ] && install -m755 "$here/bin/auraav-gui" "$prefix/bin/auraav-gui"
cp -a "$here/share/auraav/data" "$prefix/share/auraav/"
install -m644 "$here/share/applications/auraav.desktop" "$prefix/share/applications/auraav.desktop"
install -m644 "$here/share/icons/hicolor/scalable/apps/auraav.svg" \
             "$prefix/share/icons/hicolor/scalable/apps/auraav.svg"
echo
echo "Done."
echo "  GUI: $prefix/bin/auraav-gui   (or launch 'auraAV' from your app menu)"
echo "  CLI: $prefix/bin/auraav --help"
