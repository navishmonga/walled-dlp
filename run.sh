#!/usr/bin/env bash
# Start WALLED DLP (menu-bar icon on macOS). Extra args are passed through, e.g.
#   ./run.sh --discover      log every request to ChatGPT/Perplexity (endpoint discovery)
#   ./run.sh --no-tray -v    headless, verbose
cd "$(dirname "$0")"
exec .venv/bin/python -m walled_dlp run "$@"
