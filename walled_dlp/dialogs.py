"""Native OS confirmation dialogs: Continue / Cancel.

* macOS  : NSAlert via osascript `display alert` (no extra deps, works from any
           thread, comes to the front, critical icon, Cancel is default).
* Windows: user32 MessageBoxTimeoutW (topmost, system-modal, Cancel default).
* Linux  : zenity --question.

Only one dialog is shown at a time. Any failure or timeout returns "cancel"
(fail closed). For automated tests set WALLED_DLP_AUTO_DECISION=continue|cancel.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading

log = logging.getLogger("walled_dlp.dialog")
_lock = threading.Lock()

CONTINUE = "continue"
CANCEL = "cancel"

_MAC_SCRIPT = r'''
on run argv
    set theTitle to item 1 of argv
    set theMsg to item 2 of argv
    set secs to (item 3 of argv) as integer
    activate
    set r to display alert theTitle message theMsg as critical buttons {"Cancel", "Continue"} default button "Cancel" cancel button "Cancel" giving up after secs
    if gave up of r then return "timeout"
    return button returned of r
end run
'''


def ask(title: str, message: str, timeout: int = 60) -> str:
    auto = os.environ.get("WALLED_DLP_AUTO_DECISION")
    if auto:
        return CONTINUE if auto.strip().lower() == "continue" else CANCEL
    with _lock:
        try:
            if sys.platform == "darwin":
                return _ask_mac(title, message, timeout)
            if sys.platform.startswith("win"):
                return _ask_windows(title, message, timeout)
            return _ask_linux(title, message, timeout)
        except Exception:
            log.exception("dialog failed; treating as Cancel")
            return CANCEL


def _ask_mac(title: str, message: str, timeout: int) -> str:
    out = subprocess.run(
        ["/usr/bin/osascript", "-", title, message, str(int(timeout))],
        input=_MAC_SCRIPT.encode("utf-8"),
        capture_output=True,
        timeout=timeout + 15,
    )
    answer = out.stdout.decode("utf-8", errors="ignore").strip()
    # Pressing Cancel raises AppleScript error -128 -> non-zero exit, empty stdout.
    return CONTINUE if out.returncode == 0 and answer == "Continue" else CANCEL


def _ask_windows(title: str, message: str, timeout: int) -> str:  # pragma: no cover
    import ctypes

    MB_OKCANCEL = 0x1
    MB_ICONWARNING = 0x30
    MB_DEFBUTTON2 = 0x100
    MB_SYSTEMMODAL = 0x1000
    MB_SETFOREGROUND = 0x10000
    MB_TOPMOST = 0x40000
    IDOK = 1
    flags = MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST
    text = message + "\n\nOK = Continue      Cancel = Cancel"
    user32 = ctypes.windll.user32
    fn = getattr(user32, "MessageBoxTimeoutW", None)
    if fn is not None:
        res = fn(None, text, title, flags, 0, int(timeout) * 1000)
    else:
        res = user32.MessageBoxW(None, text, title, flags)
    return CONTINUE if res == IDOK else CANCEL


def _ask_linux(title: str, message: str, timeout: int) -> str:
    exe = shutil.which("zenity") or shutil.which("kdialog")
    if not exe:
        log.error("no zenity/kdialog available; cancelling")
        return CANCEL
    if exe.endswith("zenity"):
        cmd = [exe, "--question", "--title", title, "--text", message, "--ok-label=Continue",
               "--cancel-label=Cancel", "--default-cancel", f"--timeout={int(timeout)}", "--icon-name=dialog-warning"]
    else:
        cmd = [exe, "--title", title, "--warningcontinuecancel", message]
    out = subprocess.run(cmd, capture_output=True, timeout=timeout + 15)
    return CONTINUE if out.returncode == 0 else CANCEL


def notify(title: str, message: str) -> None:
    """Non-blocking informational notification (used for silent blocks)."""
    if os.environ.get("WALLED_DLP_AUTO_DECISION"):
        return
    try:
        if sys.platform == "darwin":
            subprocess.Popen(
                ["/usr/bin/osascript", "-e", "on run argv", "-e",
                 "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run",
                 title, message],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        elif shutil.which("notify-send"):
            subprocess.Popen(["notify-send", title, message])
    except Exception:
        pass
