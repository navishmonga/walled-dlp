"""mitmproxy addon: the DLP engine.

Request side
    Every POST/PUT/PATCH (and every client WebSocket message) to a target host
    is inspected *while the request is held*. If WALLED_SENSITIVE is found:
      - prompt endpoint or file upload -> native Continue/Cancel dialog
      - anything else (typing previews, telemetry, autosuggest...) -> blocked
        silently unless the user already chose Continue for the same content.
    Nothing is forwarded upstream until a decision is made.

Response side
    HTML documents from ChatGPT / Perplexity get a <style> block that recolours
    AI responses; the page's CSP is rewritten to allow exactly that style.
    All other responses (incl. SSE streams) are streamed through untouched.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from mitmproxy import http

from . import audit, dialogs
from .config import Config
from .css_inject import build_css, inject_html, rewrite_csp
from .detector import Detector, normalise
from .extractors import (
    UploadedFile,
    decode_text,
    json_strings,
    parse_multipart,
    scan_file,
    sniff_kind,
    socketio_payload,
    try_parse_json,
)

log = logging.getLogger("walled_dlp")

INSPECT_METHODS = {"POST", "PUT", "PATCH"}
CANCEL_DEDUPE_SECONDS = 8


@dataclass
class Hit:
    key: str            # content hash used for the decision cache
    label: str          # "prompt text" / file name
    snippet: str


@dataclass
class Inspection:
    hits: list[Hit] = field(default_factory=list)
    errors: list[Hit] = field(default_factory=list)   # files we could not inspect
    files: list[str] = field(default_factory=list)
    text_hit: bool = False
    file_hit: bool = False

    @property
    def empty(self) -> bool:
        return not self.hits and not self.errors


def _h(data: bytes | str) -> str:
    if isinstance(data, str):
        data = normalise(data).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class WalledDLP:
    def __init__(self, cfg: Config, on_event=None):
        self.cfg = cfg
        self.det = Detector(cfg.marker, cfg.raw.get("fuzzy_marker_regex"))
        self.enabled = True
        self._allowed: dict[str, float] = {}
        self._cancelled: dict[str, float] = {}
        self._pending: dict[str, asyncio.Future] = {}
        self._dialog_lock = asyncio.Lock()
        self._on_event = on_event
        self.stats = {"prompts_checked": 0, "files_checked": 0, "continued": 0, "cancelled": 0, "silent_blocks": 0}

    # ------------------------------------------------------------------ util
    def _emit(self, **ev):
        try:
            audit.record(**ev)
        except Exception:
            log.exception("audit write failed")
        if self._on_event:
            try:
                self._on_event(ev, dict(self.stats))
            except Exception:
                pass

    def _site_label(self, flow_req) -> str:
        site = self.cfg.site_for_host(flow_req.pretty_host)
        if site:
            return site.label
        for hdr in ("origin", "referer"):
            v = flow_req.headers.get(hdr)
            if v:
                s = self.cfg.site_for_host(urlsplit(v).hostname or "")
                if s:
                    return s.label
        return flow_req.pretty_host

    def _cache_state(self, keys: list[str]) -> str | None:
        now = time.monotonic()
        for d in (self._allowed, self._cancelled):
            for k in [k for k, exp in d.items() if exp < now]:
                d.pop(k, None)
        if keys and all(k in self._allowed for k in keys):
            return dialogs.CONTINUE
        if any(k in self._cancelled for k in keys):
            return dialogs.CANCEL
        return None

    def _remember(self, keys: list[str], decision: str):
        now = time.monotonic()
        if decision == dialogs.CONTINUE:
            for k in keys:
                self._allowed[k] = now + float(self.cfg.decision_cache_seconds)
        else:
            for k in keys:
                self._cancelled[k] = now + CANCEL_DEDUPE_SECONDS

    # ------------------------------------------------------------ inspection
    def _scan_texts(self, texts: list[str], insp: Inspection):
        seen = set()
        for t in texts:
            if not t or len(t) < len(self.cfg.marker) - 2:
                continue
            m = self.det.scan(t)
            if m.found:
                k = _h(t)
                if k not in seen:
                    seen.add(k)
                    insp.hits.append(Hit(k, "prompt text", m.snippet))
                    insp.text_hit = True

    def _scan_files(self, files: list[UploadedFile], insp: Inspection):
        for f in files:
            self.stats["files_checked"] += 1
            insp.files.append(f.filename)
            r = scan_file(f, self.det, int(self.cfg.max_inspect_bytes), int(self.cfg.max_pdf_pages_ocr))
            key = _h(f.data)
            if r.match.found:
                insp.hits.append(Hit(key, f"file “{f.filename}” ({r.kind})", r.match.snippet))
                insp.file_hit = True
            elif r.error:
                insp.errors.append(Hit(key, f"file “{f.filename}” ({r.kind})", r.error))

    def inspect_body(self, host: str, path: str, content_type: str, body: bytes) -> Inspection:
        insp = Inspection()
        ct = (content_type or "").lower()
        upload_host = self.cfg.is_upload_host(host)
        name_from_url = path.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1] or "upload"

        if ct.startswith("multipart/"):
            files, fields = parse_multipart(body, content_type)
            self._scan_files(files, insp)
            self._scan_texts(fields, insp)
            return insp

        if not upload_host:
            obj = try_parse_json(body)
            if obj is not None:
                self._scan_texts(json_strings(obj), insp)
                return insp
            if ct.startswith("application/x-www-form-urlencoded"):
                self._scan_texts([v for _, v in parse_qsl(decode_text(body), keep_blank_values=True)], insp)
                return insp

        kind = sniff_kind(body, content_type, name_from_url)
        if upload_host or kind in ("pdf", "image", "office") or ct.startswith(("application/octet-stream", "image/")):
            self._scan_files([UploadedFile(name_from_url, content_type, body)], insp)
        else:
            self._scan_texts([decode_text(body)], insp)
        return insp

    # --------------------------------------------------------------- decide
    async def _decide(self, *, site_label: str, category: str, insp: Inspection, where: str) -> str:
        """Returns CONTINUE or CANCEL. category: prompt | upload | secondary."""
        cfg = self.cfg
        keys = sorted({h.key for h in insp.hits + insp.errors})
        cached = self._cache_state(keys)
        if cached:
            self._emit(event="decision", source="cache", decision=cached, site=site_label, category=category, where=where)
            return cached

        if not insp.hits:  # only inspection errors
            policy = cfg.on_inspection_error
            if policy in ("allow", "block"):
                d = dialogs.CONTINUE if policy == "allow" else dialogs.CANCEL
                self._emit(event="decision", source="policy", decision=d, site=site_label,
                           category=category, where=where, errors=[e.snippet for e in insp.errors])
                return d

        if category == "secondary" and cfg.secondary_action == "block_silently":
            self.stats["silent_blocks"] += 1
            self._emit(event="decision", source="silent", decision=dialogs.CANCEL, site=site_label,
                       category=category, where=where)
            return dialogs.CANCEL

        fp = "|".join(keys)
        fut = self._pending.get(fp)
        if fut is not None:  # identical request already waiting on a dialog
            return await asyncio.shield(fut)
        fut = asyncio.get_running_loop().create_future()
        self._pending[fp] = fut
        try:
            async with self._dialog_lock:
                cached = self._cache_state(keys)  # decided while we waited?
                if cached:
                    decision = cached
                else:
                    title, msg = self._dialog_text(site_label, category, insp)
                    decision = await asyncio.to_thread(dialogs.ask, title, msg, int(cfg.dialog_timeout_seconds))
                    self._remember(keys, decision)
                    self.stats["continued" if decision == dialogs.CONTINUE else "cancelled"] += 1
            self._emit(event="decision", source="user", decision=decision, site=site_label, category=category,
                       where=where, files=insp.files, marker_found=bool(insp.hits),
                       errors=[e.snippet for e in insp.errors])
            fut.set_result(decision)
            return decision
        except BaseException:
            if not fut.done():
                fut.set_result(dialogs.CANCEL)
            raise
        finally:
            self._pending.pop(fp, None)

    def _dialog_text(self, site_label: str, category: str, insp: Inspection) -> tuple[str, str]:
        action = {"prompt": "send a prompt", "upload": "upload a file"}.get(category, "send data")
        lines = []
        if insp.hits:
            title = "Sensitive content detected"
            lines.append(f"You are about to {action} to {site_label}.")
            lines.append(f"The marker {self.cfg.marker} was found in:")
            for h in insp.hits[:5]:
                lines.append(f"  • {h.label}: “{h.snippet[:140]}”")
        else:
            title = "Content could not be inspected"
            lines.append(f"You are about to {action} to {site_label}, but it could not be checked for {self.cfg.marker}.")
        for e in insp.errors[:5]:
            lines.append(f"  • {e.label}: {e.snippet}")
        lines.append("")
        lines.append("Continue anyway?")
        return f"WALLED DLP — {title}", "\n".join(lines)

    def _block(self, flow: http.HTTPFlow, reason: str):
        headers = {"Content-Type": "application/json", "X-Walled-DLP": "blocked", "Cache-Control": "no-store"}
        origin = flow.request.headers.get("origin")
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        body = json.dumps({"detail": f"Blocked by WALLED DLP: {reason}", "error": "walled_dlp_blocked"})
        flow.response = http.Response.make(403, body, headers)

    # ---------------------------------------------------------- mitm hooks
    async def request(self, flow: http.HTTPFlow):
        if not self.enabled:
            return
        req = flow.request
        host = req.pretty_host
        cfg = self.cfg
        if not cfg.is_target_host(host):
            return
        if cfg.discovery_logging:
            log.info("DISCOVER %s %s%s ct=%s len=%s", req.method, host, req.path.split("?")[0],
                     req.headers.get("content-type", ""), len(req.raw_content or b""))

        site = cfg.site_for_host(host)
        if (cfg.block_service_workers and site is not None
                and req.headers.get("service-worker", "").lower() == "script"):
            flow.response = http.Response.make(404, b"", {"Cache-Control": "no-store"})
            return

        if req.method not in INSPECT_METHODS:
            return
        body = req.get_content(strict=False) or b""
        if not body:
            return

        path = req.path
        ct = req.headers.get("content-type", "")
        is_prompt_path = site is not None and site.is_prompt_path(path)
        if is_prompt_path:
            self.stats["prompts_checked"] += 1
        insp = await asyncio.to_thread(self.inspect_body, host, path, ct, body)
        if insp.empty:
            return

        if insp.file_hit or (insp.errors and not insp.text_hit) or (cfg.is_upload_host(host) and insp.text_hit):
            category = "upload"
        elif is_prompt_path:
            category = "prompt"
        else:
            category = "secondary"

        label = self._site_label(req)
        where = f"{req.method} {host}{path.split('?')[0]}"
        decision = await self._decide(site_label=label, category=category, insp=insp, where=where)
        if decision != dialogs.CONTINUE:
            reason = "upload cancelled" if category == "upload" else "content marked WALLED_SENSITIVE"
            self._block(flow, reason)
            if category == "secondary":
                dialogs.notify("WALLED DLP", f"Blocked background request to {label} containing {cfg.marker}")

    async def websocket_message(self, flow: http.HTTPFlow):
        if not self.enabled or flow.websocket is None:
            return
        msg = flow.websocket.messages[-1]
        if not msg.from_client:
            return
        host = flow.request.pretty_host
        if not self.cfg.is_target_host(host):
            return
        text = msg.text if msg.is_text else decode_text(msg.content)
        obj = socketio_payload(text) if text[:1].isdigit() else try_parse_json(text.encode())
        strings = json_strings(obj) if obj is not None else [text]
        insp = Inspection()
        self._scan_texts(strings, insp)
        if insp.empty:
            return
        site = self.cfg.site_for_host(host)
        category = "prompt" if site is not None else "secondary"
        decision = await self._decide(site_label=self._site_label(flow.request), category=category, insp=insp,
                                      where=f"WS {host}{flow.request.path.split('?')[0]}")
        if decision != dialogs.CONTINUE:
            msg.drop()

    # ------------------------------------------------------ diagnostics
    def error(self, flow: http.HTTPFlow):
        if flow.error and self.cfg.is_target_host(flow.request.pretty_host):
            log.warning("FLOW ERROR %s %s: %s", flow.request.method, flow.request.pretty_url.split("?")[0], flow.error)

    def tls_failed_client(self, data):
        sni = getattr(data.context.client, "sni", None)
        log.warning("CLIENT REJECTED OUR CERT for %s (%s) - is the WALLED DLP CA trusted by this browser?",
                    sni, getattr(data.conn, "error", ""))

    def tls_failed_server(self, data):
        sni = getattr(data.context.client, "sni", None)
        log.warning("UPSTREAM TLS FAILED for %s: %s", sni, getattr(data.conn, "error", ""))

    def client_connected(self, client):
        if self.cfg.discovery_logging:
            log.info("CLIENT CONNECTED %s", client.peername)

    # ------------------------------------------------- response recolouring
    def _should_inject(self, flow: http.HTTPFlow) -> bool:
        if not (self.enabled and self.cfg.color_responses) or flow.response is None:
            return False
        site = self.cfg.site_for_host(flow.request.pretty_host)
        if site is None or not site.response_selectors or flow.request.method != "GET":
            return False
        if flow.response.status_code != 200:
            return False
        if "text/html" not in flow.response.headers.get("content-type", "").lower():
            return False
        dest = flow.request.headers.get("sec-fetch-dest", "document").lower()
        return dest in ("document", "iframe", "")

    def responseheaders(self, flow: http.HTTPFlow):
        if self.cfg.discovery_logging and self.cfg.is_target_host(flow.request.pretty_host):
            log.info("DISCOVER <- %s %s%s ct=%s", flow.response.status_code, flow.request.pretty_host,
                     flow.request.path.split("?")[0], flow.response.headers.get("content-type", ""))
        # Buffer only the HTML pages we rewrite; stream everything else so the
        # AI's token-by-token (SSE) output is not delayed.
        if not self._should_inject(flow):
            flow.response.stream = True

    def response(self, flow: http.HTTPFlow):
        if not self._should_inject(flow) or flow.response.stream:
            return
        site = self.cfg.site_for_host(flow.request.pretty_host)
        css = build_css(site.response_selectors, self.cfg.response_color)
        try:
            html = flow.response.get_text(strict=False)
            if html is None:
                return
            flow.response.text = inject_html(html, css)
            for name in ("content-security-policy", "content-security-policy-report-only"):
                vals = flow.response.headers.get_all(name)
                if vals:
                    flow.response.headers.set_all(name, [rewrite_csp(v, css) for v in vals])
            flow.response.headers["cache-control"] = "no-store"
            flow.response.headers.pop("etag", None)
        except Exception:
            log.exception("HTML injection failed for %s", flow.request.pretty_url)
