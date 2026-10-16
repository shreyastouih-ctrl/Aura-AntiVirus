#!/bin/bash
# Double-clickable macOS installer for the auraAV .pkg on this disk image.
# If Gatekeeper blocks it: right-click -> Open, or run
#   xattr -dr com.apple.quarantine "/Volumes/auraAV .../install-macos.command"
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
pkg="$(ls "$here"/auraav-*-macos.pkg 2>/dev/null | head -1)"
if [ -z "$pkg" ]; then
  echo "No .pkg found next to this script." >&2
  read -rp "Press Enter to close..." _
  exit 1
fi
echo "Installing $(basename "$pkg") (requires admin password)..."
sudo installer -pkg "$pkg" -target /
echo
echo "Done. Launch auraAV from Applications, or run 'auraav --version' in a new terminal."
read -rp "Press Enter to close..." _
