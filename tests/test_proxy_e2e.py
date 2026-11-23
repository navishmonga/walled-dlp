"""End-to-end: real mitmproxy engine + DLP addon between curl and a local upstream.

The upstream plays the part of ChatGPT (plain HTTP on 127.0.0.1) and of the
upload storage host (HTTPS on "localhost", intercepted with our
name-constrained CA, verified by curl).
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures"
RECEIVED: list[tuple[str, str, bytes]] = []
HTML = "<!doctype html><html><head><title>t</title></head><body><div data-message-author-role=\"assistant\">hi</div></body></html>"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _body(self):
        n = int(self.headers.get("content-length", 0))
        return self.rfile.read(n) if n else b""

    def _reply(self, code, body: bytes, ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        RECEIVED.append(("GET", self.path, b""))
        self._reply(200, HTML.encode(), "text/html; charset=utf-8",
                    {"Content-Security-Policy": "default-src 'self'; style-src 'self' 'nonce-r4nd0m'"})

    def do_POST(self):  # noqa: N802
        RECEIVED.append(("POST", self.path, self._body()))
        self._reply(200, b'{"ok":true}')

    def do_PUT(self):  # noqa: N802
        RECEIVED.append(("PUT", self.path, self._body()))
        self._reply(201, b'{"ok":true}')

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    home = tmp_path_factory.mktemp("dlp_home")
    os.environ["WALLED_DLP_HOME"] = str(home)
    http_port, https_port, proxy_port, pac_port = free_port(), free_port(), free_port(), free_port()
    (home / "config.json").write_text(json.dumps({
        "proxy_port": proxy_port, "pac_port": pac_port,
        "sites": {"testsite": {"label": "TestGPT", "hosts": ["127.0.0.1"],
                               "prompt_paths": ["^/backend-api/(f/)?conversation/?$"],
                               "response_selectors": ["[data-message-author-role=\"assistant\"]"]}},
        "upload_hosts": ["localhost"],
    }))

    from walled_dlp import ca
    from walled_dlp.app import Engine
    from walled_dlp.config import load_config

    cfg = load_config()
    ca.generate_ca(cfg)

    # upstream servers
    http_srv = ThreadingHTTPServer(("127.0.0.1", http_port), Upstream)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    certdir = tmp_path_factory.mktemp("upstream_cert")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(certdir / "k.pem"), "-out", str(certdir / "c.pem")],
                   check=True, capture_output=True)
    https_srv = ThreadingHTTPServer(("127.0.0.1", https_port), Upstream)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(certdir / "c.pem", certdir / "k.pem")
    https_srv.socket = sctx.wrap_socket(https_srv.socket, server_side=True)
    threading.Thread(target=https_srv.serve_forever, daemon=True).start()

    eng = Engine(cfg, extra_options={"ssl_insecure": True})
    eng.start()
    yield {"cfg": cfg, "proxy": f"http://127.0.0.1:{proxy_port}", "http": f"http://127.0.0.1:{http_port}",
           "https": f"https://localhost:{https_port}", "ca": str(ca.public_cert_file()), "home": home,
           "eng": eng}
    eng.stop()
    http_srv.shutdown()
    https_srv.shutdown()


def curl(env, method, url, *, data=None, file=None, form=None, ctype=None, decision="cancel"):
    os.environ["WALLED_DLP_AUTO_DECISION"] = decision
    cmd = ["curl", "-s", "-o", "-", "-w", "\n%{http_code}", "-x", env["proxy"], "-X", method,
           "--cacert", env["ca"], "--noproxy", "", url]
    if ctype:
        cmd += ["-H", f"Content-Type: {ctype}"]
    if data is not None:
        cmd += ["--data-binary", data]
    if file is not None:
        cmd += ["--data-binary", f"@{file}"]
    if form is not None:
        cmd += ["-F", form]
    env_ = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    out = subprocess.run(cmd, capture_output=True, text=True, env=env_, timeout=60)
    body, _, code = out.stdout.rpartition("\n")
    return int(code or 0), body, out.stderr


def sent(path_part, needle: bytes):
    return any(path_part in p and needle in b for _, p, b in RECEIVED)


def prompt(text):
    return json.dumps({"action": "next", "messages": [{"author": {"role": "user"},
                       "content": {"content_type": "text", "parts": [text]}}]})


# ------------------------------------------------------------------ prompts
def test_clean_prompt_passes(env):
    code, _, _ = curl(env, "POST", env["http"] + "/backend-api/f/conversation", data=prompt("hello world 1"),
                      ctype="application/json")
    assert code == 200 and sent("/conversation", b"hello world 1")


def test_marked_prompt_cancel_blocks(env):
    code, body, _ = curl(env, "POST", env["http"] + "/backend-api/f/conversation",
                         data=prompt("plan A WALLED_SENSITIVE"), ctype="application/json", decision="cancel")
    assert code == 403 and "WALLED DLP" in body
    assert not sent("/conversation", b"plan A")


def test_marked_prompt_continue_passes(env):
    code, _, _ = curl(env, "POST", env["http"] + "/backend-api/f/conversation",
                      data=prompt("plan B WALLED_SENSITIVE"), ctype="application/json", decision="continue")
    assert code == 200 and sent("/conversation", b"plan B")


def test_secondary_request_blocked_silently(env):
    code, _, _ = curl(env, "POST", env["http"] + "/backend-api/f/conversation/prepare",
                      data=prompt("plan C WALLED_SENSITIVE"), ctype="application/json", decision="continue")
    assert code == 403 and not sent("/prepare", b"plan C")


def test_secondary_allowed_after_user_continued_same_text(env):
    # "plan B ..." was approved above -> telemetry carrying the same text may pass
    code, _, _ = curl(env, "POST", env["http"] + "/ces/v1/t", data=json.dumps({"p": "plan B WALLED_SENSITIVE"}),
                      ctype="application/json", decision="cancel")
    assert code == 200


# ------------------------------------------------------------------ uploads
@pytest.mark.parametrize("fname,found", [
    ("marker.txt", True), ("marker_text.pdf", True), ("marker_scanned.pdf", True), ("marker.png", True),
    ("clean.pdf", False), ("clean.png", False),
])
def test_raw_put_upload_over_tls(env, fname, found):
    code, _, err = curl(env, "PUT", env["https"] + f"/blob/{fname}", file=FIX / fname,
                        ctype="application/octet-stream", decision="cancel")
    assert code == (403 if found else 201), err
    assert sent(f"/blob/{fname}", b"") is (not found)


def test_multipart_upload_cancel_and_continue(env, tmp_path):
    code, _, _ = curl(env, "POST", env["https"] + "/s3", form=f"file=@{FIX / 'marker_text.pdf'}", decision="cancel")
    assert code == 403 and not any(p == "/s3" for _, p, _ in RECEIVED)
    # (a file cancelled seconds ago is auto-cancelled again, so use fresh content)
    fresh = tmp_path / "notes.txt"
    fresh.write_text("meeting notes WALLED_SENSITIVE v2")
    code, _, _ = curl(env, "POST", env["https"] + "/s3b", form=f"file=@{fresh}", decision="continue")
    assert code == 200 and any(p == "/s3b" for _, p, _ in RECEIVED)


# --------------------------------------------------------------- recolour
def test_html_gets_style_and_csp_hash(env):
    out = subprocess.run(["curl", "-s", "-D", "-", "-x", env["proxy"], "--noproxy", "", env["http"] + "/"],
                         capture_output=True, text=True)
    assert 'id="walled-dlp-style"' in out.stdout
    assert "#0a7d32" in out.stdout
    csp = [l for l in out.stdout.splitlines() if l.lower().startswith("content-security-policy")][0]
    assert "'sha256-" in csp and "'nonce-r4nd0m'" in csp


def test_cancelled_file_is_deduped_without_new_dialog(env):
    # same bytes as a file cancelled moments ago -> blocked even if the user would say continue
    code, _, _ = curl(env, "PUT", env["https"] + "/blob/again", file=FIX / "marker.png",
                      ctype="application/octet-stream", decision="continue")
    assert code == 403


def test_non_target_host_is_not_intercepted(env):
    from walled_dlp.app import _host_regex
    import re
    from walled_dlp.config import load_config
    pats = [_host_regex(p) for p in load_config(Path("/nonexistent/config.json")).all_host_patterns()]
    assert any(re.search(p, "chatgpt.com:443") for p in pats)
    assert any(re.search(p, "sdmntpreastus.oaiusercontent.com:443") for p in pats)
    assert not any(re.search(p, "example.com:443") for p in pats)
    assert not any(re.search(p, "notchatgpt.com:443") for p in pats)


def test_audit_log_written(env):
    from walled_dlp.audit import audit_path
    lines = [json.loads(l) for l in audit_path().read_text().splitlines()]
    assert any(e["decision"] == "cancel" and e["source"] == "user" for e in lines)
    assert any(e["source"] == "silent" for e in lines)
