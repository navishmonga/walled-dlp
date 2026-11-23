"""Detect browser extensions that override the system proxy (VPN / proxy
extensions). Such an extension makes the browser ignore the OS proxy settings,
so traffic to ChatGPT/Perplexity would bypass WALLED DLP.

This only *reads* browser profile files; it never modifies the browser.
"""
from __future__ import annotations

import glob
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path


def _browser_roots() -> dict[str, Path]:
    home = Path.home()
    if sys.platform == "darwin":
        base = home / "Library" / "Application Support"
        return {
            "Chrome": base / "Google" / "Chrome",
            "Chrome Beta": base / "Google" / "Chrome Beta",
            "Edge": base / "Microsoft Edge",
            "Brave": base / "BraveSoftware" / "Brave-Browser",
            "Arc": base / "Arc" / "User Data",
            "Chromium": base / "Chromium",
            "Vivaldi": base / "Vivaldi",
            "Opera": base / "com.operasoftware.Opera",
        }
    if sys.platform.startswith("win"):
        local = Path(os.environ.get("LOCALAPPDATA", home))
        return {
            "Chrome": local / "Google" / "Chrome" / "User Data",
            "Edge": local / "Microsoft" / "Edge" / "User Data",
            "Brave": local / "BraveSoftware" / "Brave-Browser" / "User Data",
        }
    cfg = home / ".config"
    return {"Chrome": cfg / "google-chrome", "Chromium": cfg / "chromium", "Brave": cfg / "BraveSoftware" / "Brave-Browser"}


@dataclass(frozen=True)
class ProxyOverride:
    browser: str
    profile: str
    extension_id: str
    name: str

    def __str__(self):
        return f"{self.name} ({self.browser} › {self.profile})"


def _load(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _ext_name(profile_dir: Path, ext_id: str, manifest: dict) -> str:
    name = manifest.get("name") or ext_id
    if name.startswith("__MSG_"):
        key = name[6:-2]
        for d in sorted(glob.glob(str(profile_dir / "Extensions" / ext_id / "*"))):
            default = manifest.get("default_locale", "en")
            for loc in (default, "en", "en_US"):
                msgs = _load(Path(d) / "_locales" / loc / "messages.json")
                for k, v in msgs.items():
                    if k.lower() == key.lower() and isinstance(v, dict) and v.get("message"):
                        return v["message"]
    return name


def find_proxy_overrides(roots: dict[str, Path] | None = None) -> list[ProxyOverride]:
    found: list[ProxyOverride] = []
    for browser, root in (roots or _browser_roots()).items():
        if not root.is_dir():
            continue
        local_state = _load(root / "Local State")
        names = local_state.get("profile", {}).get("info_cache", {})
        for prof in sorted(p for p in root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))):
            settings: dict = {}
            for f in ("Preferences", "Secure Preferences"):
                settings.update(_load(prof / f).get("extensions", {}).get("settings", {}))
            for ext_id, s in settings.items():
                if not isinstance(s, dict):
                    continue
                controls = (s.get("preferences", {}) or {}).get("proxy") or \
                           (s.get("regular_only_preferences", {}) or {}).get("proxy")
                disabled = s.get("state", 1) == 0 or bool(s.get("disable_reasons"))
                if controls and not disabled:
                    label = names.get(prof.name, {}).get("name") or prof.name
                    found.append(ProxyOverride(browser, f"{label} [{prof.name}]", ext_id,
                                               _ext_name(prof, ext_id, s.get("manifest", {}))))
    return found
