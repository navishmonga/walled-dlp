"""Inject a <style> block into ChatGPT / Perplexity HTML and keep CSP happy."""
from __future__ import annotations

import base64
import hashlib
import re

STYLE_ID = "walled-dlp-style"


def build_css(selectors: list[str], color: str) -> str:
    rules = []
    for sel in selectors:
        # One rule per selector so a selector a browser rejects doesn't drop
        # the others. Code blocks keep their syntax highlighting.
        rules.append(
            f"{sel}, {sel} *:not(pre):not(pre *):not(code):not(svg):not(svg *) {{ color: {color} !important; }}"
        )
        # Tailwind typography variables used by both apps' markdown renderers.
        rules.append(
            f"{sel} {{ --tw-prose-body: {color}; --tw-prose-headings: {color}; --tw-prose-bold: {color};"
            f" --tw-prose-bullets: {color}; --tw-prose-counters: {color}; --tw-prose-quotes: {color};"
            f" --tw-prose-links: {color}; --text-primary: {color}; }}"
        )
    return "\n".join(rules)


def css_hash(css: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode() + "'"


def _rewrite_policy(policy: str, source_hash: str) -> str:
    """Allow our inline <style> in a single CSP policy string."""
    directives = [d.strip() for d in policy.split(";") if d.strip()]
    names = [d.split()[0].lower() for d in directives]
    # Which directive governs <style> elements?
    for target in ("style-src-elem", "style-src", "default-src"):
        if target in names:
            break
    else:
        return policy  # no restriction on styles
    i = names.index(target)
    parts = directives[i].split()
    srcs = [p.lower() for p in parts[1:]]
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in srcs)
    if "'unsafe-inline'" in srcs and not has_nonce_or_hash:
        return policy  # inline styles already allowed; adding a hash would disable that
    parts = [p for p in parts if p.lower() != "'none'"]
    if source_hash not in parts:
        parts.append(source_hash)
    directives[i] = " ".join(parts)
    return "; ".join(directives)


def rewrite_csp(header_value: str, css: str) -> str:
    h = css_hash(css)
    # A header may carry several comma-separated policies.
    return ", ".join(_rewrite_policy(p, h) for p in header_value.split(","))


_META_CSP = re.compile(
    r'(<meta[^>]+http-equiv=["\']?content-security-policy["\']?[^>]*content=")([^"]*)(")', re.I
)


def inject_html(html: str, css: str) -> str:
    if STYLE_ID in html:
        return html
    tag = f'<style id="{STYLE_ID}">{css}</style>'
    html = _META_CSP.sub(lambda m: m.group(1) + rewrite_csp(m.group(2), css) + m.group(3), html)
    m = re.search(r"</head\s*>", html, re.I)
    if m:
        return html[: m.start()] + tag + html[m.start():]
    m = re.search(r"<html[^>]*>", html, re.I)
    if m:
        return html[: m.end()] + tag + html[m.end():]
    return tag + html
