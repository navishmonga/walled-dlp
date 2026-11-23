#!/usr/bin/env bash
# One-time install for WALLED DLP (macOS / Linux).
#   ./install.sh              -> venv + deps + CA setup
#   ./install.sh --autostart  -> same, and start automatically at login (macOS)
set -euo pipefail
cd "$(dirname "$0")"

PY=""
for c in python3.13 python3.12 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /usr/local/bin/python3.12 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
    PY="$c"; break
  fi
done
if [[ -z "$PY" ]]; then
  echo "Python 3.12+ is required. Install it with:  brew install python@3.12   (then re-run ./install.sh)"
  exit 1
fi
echo "Using $($PY --version) at $(command -v "$PY")"

"$PY" -m venv .venv
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt
.venv/bin/python -m walled_dlp setup "$@"
echo
echo "Start the app with:  ./run.sh"
