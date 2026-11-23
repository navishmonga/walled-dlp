"""Configuration loading and app paths.

The shipped defaults live in config.default.json next to this file. A user/admin
override file (config.json in the app data folder) is deep-merged on top, so an
admin can update endpoints, hosts or colours without shipping a new build.
"""
from __future__ import annotations

import copy
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "WalledDLP"
_DEFAULT_FILE = Path(__file__).with_name("config.default.json")


def app_home() -> Path:
    """Folder holding config.json, the CA and runtime state."""
    override = os.environ.get("WALLED_DLP_HOME")
    if override:
        p = Path(override)
    elif sys.platform == "darwin":
        p = Path.home() / "Library" / "Application Support" / APP_NAME
    elif sys.platform.startswith("win"):
        p = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
    else:
        p = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "walled-dlp"
    p.mkdir(parents=True, exist_ok=True)
    return p


def log_dir() -> Path:
    override = os.environ.get("WALLED_DLP_HOME")
    if override:
        p = Path(override) / "logs"
    elif sys.platform == "darwin":
        p = Path.home() / "Library" / "Logs" / APP_NAME
    else:
        p = app_home() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def host_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return fnmatch.fnmatchcase(host, pattern)


@dataclass
class Site:
    key: str
    label: str
    hosts: list[str]
    prompt_paths: list[re.Pattern]
    response_selectors: list[str]

    def matches_host(self, host: str) -> bool:
        return any(host_matches(host, h) for h in self.hosts)

    def is_prompt_path(self, path: str) -> bool:
        path = path.split("?", 1)[0]
        return any(p.search(path) for p in self.prompt_paths)


@dataclass
class Config:
    raw: dict
    sites: list[Site] = field(default_factory=list)

    # --- convenience accessors -------------------------------------------
    def __getattr__(self, item):
        try:
            return self.raw[item]
        except KeyError as e:
            raise AttributeError(item) from e

    def site_for_host(self, host: str) -> Site | None:
        for s in self.sites:
            if s.matches_host(host):
                return s
        return None

    def is_upload_host(self, host: str) -> bool:
        return any(host_matches(host, h) for h in self.raw["upload_hosts"])

    def is_target_host(self, host: str) -> bool:
        return self.site_for_host(host) is not None or self.is_upload_host(host)

    def all_host_patterns(self) -> list[str]:
        pats: list[str] = []
        for s in self.sites:
            pats.extend(s.hosts)
        pats.extend(self.raw["upload_hosts"])
        return pats

    def constraint_domains(self) -> list[str]:
        """Registrable-ish domains used as X.509 name constraints for the CA."""
        doms: set[str] = set()
        for p in self.all_host_patterns():
            p = p.lower()
            if p.startswith("*."):
                p = p[2:]
            if "*" in p or "?" in p:
                # Wildcards in the middle can't be expressed; constrain to the
                # part after the last wildcard label.
                p = p.split("*")[-1].lstrip(".")
            # dNSName constraints match the name and all subdomains, so
            # collapse "www.perplexity.ai" into "perplexity.ai" when both exist.
            doms.add(p)
        out = sorted(d for d in doms if not any(d != o and d.endswith("." + o) for o in doms))
        return out


def load_config(path: Path | None = None) -> Config:
    raw = json.loads(_DEFAULT_FILE.read_text())
    user_file = path or (app_home() / "config.json")
    if user_file.exists():
        raw = _deep_merge(raw, json.loads(user_file.read_text()))
    sites = [
        Site(
            key=k,
            label=v.get("label", k),
            hosts=v["hosts"],
            prompt_paths=[re.compile(p) for p in v.get("prompt_paths", [])],
            response_selectors=v.get("response_selectors", []),
        )
        for k, v in raw["sites"].items()
        if v.get("enabled", True)
    ]
    return Config(raw=raw, sites=sites)
