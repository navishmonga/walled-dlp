"""Append-only JSONL audit log of every DLP decision (no content is stored)."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from .config import log_dir

_lock = threading.Lock()


def audit_path() -> Path:
    return log_dir() / "audit.jsonl"


def record(**event) -> None:
    event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event}
    line = json.dumps(event, ensure_ascii=False)
    with _lock, audit_path().open("a", encoding="utf-8") as f:
        f.write(line + "\n")
