#!/usr/bin/env bash
# Build a standalone WALLED DLP app with PyInstaller.
#   macOS  -> dist/WalledDLP.app  (menu-bar only app, no Dock icon)
#   Linux  -> dist/WalledDLP/WalledDLP
# Run from the project root after ./install.sh:   ./packaging/build_app.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PY:-.venv/bin/python}"
"$PY" -m pip install -q "pyinstaller>=6.6"
EXTRA=()
if [[ "$(uname)" == "Darwin" ]]; then
  EXTRA+=(--windowed --osx-bundle-identifier com.walleddlp.agent --collect-all rumps --hidden-import Vision --hidden-import Foundation)
fi
"$PY" -m PyInstaller --noconfirm --clean --name WalledDLP \
  --add-data "walled_dlp/config.default.json:walled_dlp" \
  --collect-all mitmproxy --collect-all mitmproxy_rs --collect-all pypdfium2 --collect-all pypdfium2_raw \
  --collect-submodules walled_dlp \
  "${EXTRA[@]}" packaging/entry.py
if [[ "$(uname)" == "Darwin" ]]; then
  # Menu-bar app: hide the Dock icon
  /usr/libexec/PlistBuddy -c "Add :LSUIElement bool true" dist/WalledDLP.app/Contents/Info.plist 2>/dev/null || \
  /usr/libexec/PlistBuddy -c "Set :LSUIElement true" dist/WalledDLP.app/Contents/Info.plist
  echo "Built dist/WalledDLP.app  (CLI inside: dist/WalledDLP.app/Contents/MacOS/WalledDLP status)"
else
  echo "Built dist/WalledDLP/WalledDLP"
fi
