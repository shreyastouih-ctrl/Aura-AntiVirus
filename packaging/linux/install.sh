#!/usr/bin/env bash
# Portable installer for the auraAV .tar.gz bundle.
#
#   ./install.sh [--prefix /usr/local]
#
# The binary discovers its data via the executable's location, so any prefix
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
src_bin="$here/bin/auraav"
src_data="$here/share/auraav/data"
[ -x "$src_bin" ] || { echo "missing $src_bin" >&2; exit 1; }

echo "Installing auraAV to $prefix"
install -d "$prefix/bin" "$prefix/share/auraav"
install -m755 "$src_bin" "$prefix/bin/auraav"
cp -a "$src_data" "$prefix/share/auraav/"
echo "Done. Try: $prefix/bin/auraav --version"
