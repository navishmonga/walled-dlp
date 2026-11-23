"""Application runtime: proxy engine thread, PAC server, OS proxy, tray UI."""
from __future__ import annotations

import asyncio
import atexit
import fnmatch
import logging
import logging.handlers
import re
import signal
import socket
import subprocess
import sys
import threading
import time

from . import __version__, ca, system_proxy
from .addon import WalledDLP
from .audit import audit_path
from .config import Config, app_home, load_config, log_dir

log = logging.getLogger("walled_dlp")


def setup_logging(verbose: bool = False):
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(log_dir() / "walled-dlp.log", maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.handlers[:] = [fh, sh]
    # mitmproxy is chatty at INFO (every connection)
    logging.getLogger("mitmproxy").setLevel(logging.INFO if verbose else logging.WARNING)


def _host_regex(pattern: str) -> str:
    p = pattern.lower()
    if p.startswith("*."):
        core = r"(?:[^:]+\.)?" + re.escape(p[2:])
    else:
        core = fnmatch.translate(p).replace(r"\Z", "").replace("(?s:", "(?:")
    return rf"^{core}(?::\d+)?$"


class Engine:
    """Runs mitmproxy with the DLP addon in a background thread."""

    def __init__(self, cfg: Config, on_event=None, extra_options: dict | None = None):
        self.cfg = cfg
        self.extra_options = extra_options or {}
        self.addon = WalledDLP(cfg, on_event=on_event)
        self.master = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None
        self.error: BaseException | None = None

    async def _main(self):
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        opts = options.Options(
            listen_host=self.cfg.proxy_host,
            listen_port=int(self.cfg.proxy_port),
            confdir=str(ca.ca_dir()),
            allow_hosts=[_host_regex(p) for p in self.cfg.all_host_patterns()],
            http3=False,
        )
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.master.addons.add(self.addon)
        if self.extra_options:  # used by tests (e.g. ssl_insecure for a local upstream)
            self.master.options.update(**self.extra_options)
        await self.master.run()

    def _run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._main())
        except BaseException as e:  # noqa: BLE001
            self.error = e
            log.exception("proxy engine stopped with error")

    def start(self, wait: float = 15.0):
        self.thread = threading.Thread(target=self._run, name="dlp-proxy", daemon=True)
        self.thread.start()
        deadline = time.time() + wait
        while time.time() < deadline:
            if self.error:
                raise RuntimeError(f"proxy failed to start: {self.error}")
            try:
                with socket.create_connection((self.cfg.proxy_host, int(self.cfg.proxy_port)), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.2)
        raise RuntimeError("proxy did not start listening in time")

    def stop(self):
        if self.master and self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.master.shutdown)
        if self.thread:
            self.thread.join(timeout=5)


def _port_free(host: str, port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


class App:
    def __init__(self, cfg: Config, set_system_proxy: bool = True):
        self.cfg = cfg
        self.set_system_proxy = set_system_proxy
        self.engine = Engine(cfg)
        self.pac = None
        self._stopped = False

    def start(self):
        for port in (self.cfg.proxy_port, self.cfg.pac_port):
            if not _port_free(self.cfg.proxy_host, int(port)):
                raise SystemExit(f"Port {port} is already in use - is WALLED DLP already running?")
        if not ca.ca_exists():
            log.info("No CA found - generating one and adding it to the trust store")
            ca.generate_ca(self.cfg)
            ca.install_trust()
        self.engine.start()
        log.info("DLP proxy listening on %s:%s", self.cfg.proxy_host, self.cfg.proxy_port)
        self.pac = system_proxy.start_pac_server(self.cfg)
        if self.set_system_proxy:
            system_proxy.enable(self.cfg)
        atexit.register(self.stop)
        log.info("WALLED DLP %s active. Audit log: %s", __version__, audit_path())

    def stop(self):
        if self._stopped:
            return
        self._stopped = True
        log.info("Shutting down")
        if self.set_system_proxy:
            try:
                system_proxy.restore()
            except Exception:
                log.exception("could not restore proxy settings")
        if self.pac:
            self.pac.shutdown()
        self.engine.stop()


# --------------------------------------------------------------------------
# UI loops
# --------------------------------------------------------------------------
def _open(path):
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    elif sys.platform.startswith("win"):
        import os
        os.startfile(str(path))  # type: ignore[attr-defined]
    else:
        subprocess.Popen(["xdg-open", str(path)])


def run_tray(app: App):  # pragma: no cover - needs a GUI session
    import rumps

    addon = app.engine.addon

    class Tray(rumps.App):
        def __init__(self):
            super().__init__("WALLED DLP", title="🛡 DLP", quit_button=None)
            self.status = rumps.MenuItem("Protection: ON")
            self.toggle = rumps.MenuItem("Pause protection", callback=self.on_toggle)
            self.colour = rumps.MenuItem("Recolour AI responses", callback=self.on_colour)
            self.colour.state = int(bool(app.cfg.color_responses))
            self.stats = rumps.MenuItem("")
            self.menu = [
                self.status, self.stats, None, self.toggle, self.colour, None,
                rumps.MenuItem("Open audit log", callback=lambda _: _open(audit_path())),
                rumps.MenuItem("Open config folder", callback=lambda _: _open(app_home())),
                None,
                rumps.MenuItem("Quit WALLED DLP", callback=self.on_quit),
            ]
            self.timer = rumps.Timer(self.refresh, 2)
            self.timer.start()

        def refresh(self, _=None):
            s = addon.stats
            self.stats.title = (f"Checked {s['prompts_checked']} prompts · {s['files_checked']} files · "
                                f"{s['continued']} continued · {s['cancelled'] + s['silent_blocks']} blocked")
            if app.engine.error:
                self.status.title = "Protection: ERROR (see log)"
                self.title = "🛡 DLP ⚠︎"

        def on_toggle(self, item):
            addon.enabled = not addon.enabled
            self.status.title = "Protection: ON" if addon.enabled else "Protection: PAUSED"
            item.title = "Pause protection" if addon.enabled else "Resume protection"
            self.title = "🛡 DLP" if addon.enabled else "🛡 DLP (paused)"
            log.warning("Protection %s by user", "resumed" if addon.enabled else "PAUSED")

        def on_colour(self, item):
            app.cfg.raw["color_responses"] = not app.cfg.color_responses
            item.state = int(app.cfg.color_responses)
            rumps.notification("WALLED DLP", "", "Reload ChatGPT / Perplexity to apply the colour change.")

        def on_quit(self, _):
            app.stop()
            rumps.quit_application()

    Tray().run()


def run_headless(app: App):
    stop = threading.Event()

    def _sig(*_):
        stop.set()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    while not stop.is_set() and (app.engine.thread and app.engine.thread.is_alive()):
        stop.wait(1)
    app.stop()


def main_run(tray: bool = True, set_system_proxy: bool = True, discover: bool = False, verbose: bool = False):
    setup_logging(verbose)
    cfg = load_config()
    if discover:
        cfg.raw["discovery_logging"] = True
    app = App(cfg, set_system_proxy=set_system_proxy)
    app.start()
    signal.signal(signal.SIGTERM, lambda *_: (app.stop(), sys.exit(0)))
    if tray:
        try:
            import rumps  # noqa: F401
        except ImportError:
            log.warning("rumps not installed - running without a menu-bar icon")
            tray = False
    if tray and sys.platform == "darwin":
        run_tray(app)
    else:
        run_headless(app)
