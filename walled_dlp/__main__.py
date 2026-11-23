"""WALLED DLP command line.

    python -m walled_dlp setup              # create CA, trust it, (optionally) autostart
    python -m walled_dlp run                # start the app (menu-bar icon on macOS)
    python -m walled_dlp run --discover     # also log every request to target hosts
    python -m walled_dlp status
    python -m walled_dlp scan FILE...       # test detection/OCR on local files
    python -m walled_dlp test-dialog        # show the native dialog once
    python -m walled_dlp uninstall          # restore proxy, remove CA + autostart
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

from . import __version__, ca, dialogs, system_proxy
from .config import app_home, load_config, log_dir

LAUNCH_AGENT = Path.home() / "Library" / "LaunchAgents" / "com.walleddlp.agent.plist"


def _launch_agent_plist() -> str:
    project = Path(__file__).resolve().parent.parent
    if getattr(sys, "frozen", False):  # packaged .app / binary
        prog = f"<string>{sys.executable}</string><string>run</string>"
    else:
        prog = f"<string>{sys.executable}</string><string>-m</string><string>walled_dlp</string><string>run</string>"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.walleddlp.agent</string>
  <key>ProgramArguments</key>
  <array>
    {prog}
  </array>
  <key>WorkingDirectory</key><string>{project}</string>
  <key>EnvironmentVariables</key><dict><key>PYTHONPATH</key><string>{project}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>{log_dir() / 'launchd.out.log'}</string>
  <key>StandardErrorPath</key><string>{log_dir() / 'launchd.err.log'}</string>
</dict>
</plist>
"""


def cmd_setup(args):
    cfg = load_config()
    if ca.ca_exists() and not args.force:
        print("CA already exists:", ca.public_cert_file())
    else:
        ca.generate_ca(cfg)
        print("Generated name-constrained CA:", ca.public_cert_file())
    print("Permitted domains:", ", ".join(cfg.constraint_domains()))
    print("SHA-256 fingerprint:", ca.fingerprint())
    print("Adding the CA to your trust store (macOS will ask for your password)...")
    ca.install_trust()
    if args.autostart and sys.platform == "darwin":
        LAUNCH_AGENT.parent.mkdir(parents=True, exist_ok=True)
        LAUNCH_AGENT.write_text(_launch_agent_plist())
        subprocess.run(["launchctl", "unload", str(LAUNCH_AGENT)], capture_output=True)
        subprocess.run(["launchctl", "load", "-w", str(LAUNCH_AGENT)], check=False)
        print("Autostart enabled:", LAUNCH_AGENT)
    user_cfg = app_home() / "config.json"
    if not user_cfg.exists():
        user_cfg.write_text(json.dumps({"_comment": "Overrides for config.default.json"}, indent=2))
    print("\nDone. Start with:  python -m walled_dlp run")
    print("Restart your browser once so it picks up the new certificate.")


def cmd_run(args):
    from .app import main_run
    main_run(tray=not args.no_tray, set_system_proxy=not args.no_system_proxy,
             discover=args.discover, verbose=args.verbose)


def cmd_uninstall(args):
    system_proxy.restore()
    if sys.platform == "darwin" and LAUNCH_AGENT.exists():
        subprocess.run(["launchctl", "unload", "-w", str(LAUNCH_AGENT)], capture_output=True)
        LAUNCH_AGENT.unlink()
        print("Removed autostart agent")
    ca.uninstall_trust()
    print("Removed CA from trust store. App data kept in", app_home())


def cmd_status(args):
    cfg = load_config()
    def listening(port):
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=0.5):
                return True
        except OSError:
            return False
    print("WALLED DLP", __version__)
    print("App data     :", app_home())
    print("Logs         :", log_dir())
    print("CA present   :", ca.ca_exists(), f"({ca.fingerprint()})" if ca.ca_exists() else "")
    print("Proxy running:", listening(cfg.proxy_port), f"127.0.0.1:{cfg.proxy_port}")
    print("PAC running  :", listening(cfg.pac_port), f"http://127.0.0.1:{cfg.pac_port}/proxy.pac")
    print("Autostart    :", LAUNCH_AGENT.exists())
    print("Target hosts :", ", ".join(cfg.all_host_patterns()))


def cmd_scan(args):
    from .detector import Detector
    from .extractors import UploadedFile, scan_file
    cfg = load_config()
    det = Detector(cfg.marker, cfg.raw.get("fuzzy_marker_regex"))
    for p in args.files:
        data = Path(p).read_bytes()
        r = scan_file(UploadedFile(Path(p).name, "", data), det, int(cfg.max_inspect_bytes), int(cfg.max_pdf_pages_ocr))
        status = "MARKER FOUND" if r.match.found else ("CANNOT INSPECT" if r.error else "clean")
        print(f"{status:14} [{r.kind}] {p}" + (f"  “{r.match.snippet}”" if r.match.found else "")
              + (f"  ({r.error})" if r.error else ""))


def cmd_test_dialog(args):
    d = dialogs.ask("WALLED DLP — Sensitive content detected",
                    "You are about to send a prompt to ChatGPT.\nThe marker WALLED_SENSITIVE was found in:\n"
                    "  • prompt text: “… quarterly WALLED_SENSITIVE numbers …”\n\nContinue anyway?", 30)
    print("Decision:", d)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="walled_dlp", description="WALLED DLP desktop agent")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("setup"); s.add_argument("--force", action="store_true", help="regenerate the CA")
    s.add_argument("--autostart", action="store_true", help="start at login (macOS LaunchAgent)")
    s.set_defaults(fn=cmd_setup)
    r = sub.add_parser("run")
    r.add_argument("--no-tray", action="store_true")
    r.add_argument("--no-system-proxy", action="store_true", help="don't change OS proxy settings")
    r.add_argument("--discover", action="store_true", help="log every request to target hosts")
    r.add_argument("-v", "--verbose", action="store_true")
    r.set_defaults(fn=cmd_run)
    sub.add_parser("uninstall").set_defaults(fn=cmd_uninstall)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    sc = sub.add_parser("scan"); sc.add_argument("files", nargs="+"); sc.set_defaults(fn=cmd_scan)
    sub.add_parser("test-dialog").set_defaults(fn=cmd_test_dialog)
    if argv is None:
        argv = [a for a in sys.argv[1:] if not a.startswith("-psn_")]  # Finder launch arg
    args = ap.parse_args(argv)
    if not getattr(args, "fn", None):
        args = ap.parse_args(["run", *argv])
    args.fn(args)


if __name__ == "__main__":
    main()
