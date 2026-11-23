"""Marker detection with normalisation against common evasion / OCR noise."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Zero-width and other invisible format characters people (or editors) insert.
_INVISIBLE = re.compile(
    "[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮"
    "⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ]"
)
# Characters that commonly stand in for "_" (OCR, fancy fonts, PDFs).
_UNDERSCORE_LIKE = str.maketrans({c: "_" for c in "＿‗ˍ̲‿⁀⁔︳︴﹍﹎﹏"})


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = text.translate(_UNDERSCORE_LIKE)
    return text


@dataclass
class Match:
    found: bool
    snippet: str = ""
    exact: bool = False


class Detector:
    def __init__(self, marker: str, fuzzy_regex: str | None = None):
        self.marker = marker
        self._exact = re.compile(re.escape(marker))
        self._fuzzy = re.compile(fuzzy_regex, re.IGNORECASE) if fuzzy_regex else None

    def scan(self, text: str, fuzzy: bool = False) -> Match:
        """Scan text. `fuzzy` is used for OCR / PDF output where the underscore
        or spacing may be mangled. Exact match is case-sensitive."""
        if not text:
            return Match(False)
        norm = normalise(text)
        m = self._exact.search(norm)
        exact = m is not None
        if m is None:
            # Line-wrapped in PDFs/OCR: drop newlines + hyphenation and retry.
            joined = re.sub(r"-?\s*\n\s*", "", norm)
            m = self._exact.search(joined)
            if m is not None:
                norm = joined
        if m is None and fuzzy and self._fuzzy is not None:
            m = self._fuzzy.search(norm)
        if m is None:
            return Match(False)
        return Match(True, _snippet(norm, m.start(), m.end()), exact)


def _snippet(text: str, start: int, end: int, width: int = 40) -> str:
    a = max(0, start - width)
    b = min(len(text), end + width)
    s = text[a:b].replace("\n", " ").strip()
    s = re.sub(r"\s+", " ", s)
    return ("…" if a > 0 else "") + s + ("…" if b < len(text) else "")
