"""PAC server + OS proxy configuration.

Only the target hosts are routed to the local proxy (via a PAC file); every
other site goes DIRECT and is never touched. Previous OS settings are saved to
state.json and restored on exit / uninstall (also after a crash, on next start).
"""
from __future__ import annotations

import json
import logging
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import Config, app_home

log = logging.getLogger("walled_dlp.proxy")
STATE_FILE = "proxy_state.json"


# --------------------------------------------------------------------------
# PAC
# --------------------------------------------------------------------------
def build_pac(cfg: Config) -> str:
    checks = []
    for pat in cfg.all_host_patterns():
        p = pat.lower()
        if p.startswith("*."):
            base = p[2:]
            checks.append(f'host === "{base}" || dnsDomainIs(host, ".{base}")')
        elif "*" in p or "?" in p:
            checks.append(f'shExpMatch(host, "{p}")')
        else:
            checks.append(f'host === "{p}"')
    cond = "\n      || ".join(checks)
    proxy = f"PROXY {cfg.proxy_host}:{cfg.proxy_port}"
    return f"""// WALLED DLP - routes only AI-app traffic through the local DLP proxy
function FindProxyForURL(url, host) {{
  host = host.toLowerCase();
  if ({cond}) {{
    return "{proxy}";
  }}
  return "DIRECT";
}}
"""


class _PacHandler(BaseHTTPRequestHandler):
    pac: bytes = b""

    def do_GET(self):  # noqa: N802
        if self.path.split("?")[0] not in ("/proxy.pac", "/wpad.dat"):
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(self.pac)))
        self.end_headers()
        self.wfile.write(self.pac)

    def log_message(self, *a):
        pass


def start_pac_server(cfg: Config) -> ThreadingHTTPServer:
    handler = type("PacHandler", (_PacHandler,), {"pac": build_pac(cfg).encode()})
    srv = ThreadingHTTPServer(("127.0.0.1", int(cfg.pac_port)), handler)
    threading.Thread(target=srv.serve_forever, name="pac-server", daemon=True).start()
    return srv


def pac_url(cfg: Config) -> str:
    return f"http://127.0.0.1:{cfg.pac_port}/proxy.pac?v={int(time.time())}"


# --------------------------------------------------------------------------
# OS integration
# --------------------------------------------------------------------------
def _state_path():
    return app_home() / STATE_FILE


def _save_state(state: dict):
    p = _state_path()
    if not p.exists():  # never overwrite the *original* settings
        p.write_text(json.dumps(state, indent=2))


def _load_state() -> dict | None:
    p = _state_path()
    return json.loads(p.read_text()) if p.exists() else None


def _clear_state():
    _state_path().unlink(missing_ok=True)


# ---- macOS ---------------------------------------------------------------
def _mac_services() -> list[str]:
    out = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True).stdout
    return [l.strip() for l in out.splitlines()[1:] if l.strip() and not l.startswith("*")]


def _mac_get_autoproxy(svc: str) -> dict:
    out = subprocess.run(["networksetup", "-getautoproxyurl", svc], capture_output=True, text=True).stdout
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip().lower()] = v.strip()
    return {"url": d.get("url", "(null)"), "enabled": d.get("enabled", "No") == "Yes"}


def _mac_run(cmds: list[list[str]]):
    """Run networksetup commands; escalate once via a macOS admin prompt if needed."""
    failed = []
    for c in cmds:
        r = subprocess.run(c, capture_output=True, text=True)
        if r.returncode != 0 or "requires admin" in (r.stdout + r.stderr).lower():
            failed.append(c)
    if failed:
        script = " && ".join(shlex.join(c) for c in failed)
        osa = f'do shell script {json.dumps(script)} with administrator privileges'
        subprocess.run(["osascript", "-e", osa], check=True)


def _mac_enable(url: str):
    services = _mac_services()
    _save_state({"platform": "darwin", "services": {s: _mac_get_autoproxy(s) for s in services}})
    cmds = []
    for s in services:
        cmds.append(["networksetup", "-setautoproxyurl", s, url])
        cmds.append(["networksetup", "-setautoproxystate", s, "on"])
    _mac_run(cmds)


def _mac_restore(state: dict):
    cmds = []
    for s, prev in state.get("services", {}).items():
        if prev.get("enabled") and prev.get("url") not in (None, "", "(null)"):
            cmds.append(["networksetup", "-setautoproxyurl", s, prev["url"]])
            cmds.append(["networksetup", "-setautoproxystate", s, "on"])
        else:
            cmds.append(["networksetup", "-setautoproxystate", s, "off"])
    if cmds:
        _mac_run(cmds)


# ---- Windows -------------------------------------------------------------
_WIN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _win_refresh():  # pragma: no cover
    import ctypes
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH


def _win_enable(url: str):  # pragma: no cover
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY, 0, winreg.KEY_ALL_ACCESS) as k:
        try:
            prev = winreg.QueryValueEx(k, "AutoConfigURL")[0]
        except FileNotFoundError:
            prev = None
        _save_state({"platform": "win32", "AutoConfigURL": prev})
        winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, url)
    _win_refresh()


def _win_restore(state: dict):  # pragma: no cover
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY, 0, winreg.KEY_ALL_ACCESS) as k:
        if state.get("AutoConfigURL"):
            winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, state["AutoConfigURL"])
        else:
            try:
                winreg.DeleteValue(k, "AutoConfigURL")
            except FileNotFoundError:
                pass
    _win_refresh()


# ---- Linux (GNOME) -------------------------------------------------------
def _gs(*args) -> str:
    return subprocess.run(["gsettings", *args], capture_output=True, text=True).stdout.strip()


def _linux_enable(url: str):
    _save_state({"platform": "linux", "mode": _gs("get", "org.gnome.system.proxy", "mode"),
                 "url": _gs("get", "org.gnome.system.proxy", "autoconfig-url")})
    _gs("set", "org.gnome.system.proxy", "autoconfig-url", url)
    _gs("set", "org.gnome.system.proxy", "mode", "auto")


def _linux_restore(state: dict):
    _gs("set", "org.gnome.system.proxy", "autoconfig-url", state.get("url", "''").strip("'"))
    _gs("set", "org.gnome.system.proxy", "mode", state.get("mode", "'none'").strip("'"))


# ---- public --------------------------------------------------------------
def enable(cfg: Config):
    url = pac_url(cfg)
    log.info("Setting system auto-proxy (PAC) to %s", url)
    if sys.platform == "darwin":
        _mac_enable(url)
    elif sys.platform.startswith("win"):
        _win_enable(url)
    else:
        _linux_enable(url)


def restore():
    state = _load_state()
    if not state:
        return
    log.info("Restoring previous proxy settings")
    try:
        if state["platform"] == "darwin":
            _mac_restore(state)
        elif state["platform"] == "win32":
            _win_restore(state)
        else:
            _linux_restore(state)
    finally:
        _clear_state()
