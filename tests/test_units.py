from pathlib import Path

import pytest

from walled_dlp.config import load_config, host_matches
from walled_dlp.css_inject import build_css, css_hash, inject_html, rewrite_csp
from walled_dlp.detector import Detector
from walled_dlp.extractors import UploadedFile, parse_multipart, scan_file, socketio_payload, json_strings

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def cfg(tmp_path_factory):
    import os
    os.environ["WALLED_DLP_HOME"] = str(tmp_path_factory.mktemp("home"))
    return load_config()


@pytest.fixture(scope="module")
def det(cfg):
    return Detector(cfg.marker, cfg.fuzzy_marker_regex)


# ---------------------------------------------------------------- detector
@pytest.mark.parametrize("text,found", [
    ("please WALLED_SENSITIVE thanks", True),
    ("WALLED​_SENSITIVE", True),                 # zero-width space
    ("ＷＡＬＬＥＤ＿ＳＥＮＳＩＴＩＶＥ", True),           # full-width (NFKC)
    ("WALLED_SEN-\nSITIVE", True),                    # wrapped
    ("walled_sensitive", False),                      # exact match is case-sensitive
    ("WALLED SENSITIVE", False),                      # not fuzzy for typed text
    ("nothing here", False),
])
def test_detector(det, text, found):
    assert det.scan(text).found is found


def test_detector_fuzzy_for_ocr(det):
    assert det.scan("WALLED SENSITIVE", fuzzy=True).found
    assert det.scan("WALLED-SENSlTIVE", fuzzy=True).found is False


# -------------------------------------------------------------- extractors
@pytest.mark.parametrize("name,found", [
    ("marker.txt", True), ("clean.txt", False), ("marker_zero_width.txt", True),
    ("marker_text.pdf", True), ("marker_wrapped.pdf", True), ("clean.pdf", False),
    ("marker_scanned.pdf", True), ("marker.png", True), ("clean.png", False),
])
def test_fixture_files(cfg, det, name, found):
    r = scan_file(UploadedFile(name, "", (FIX / name).read_bytes()), det, cfg.max_inspect_bytes, 5)
    assert r.error is None
    assert r.match.found is found


def test_multipart_parse():
    body = (b"--XB\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nuploads/abc\r\n"
            b"--XB\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n"
            b"Content-Type: text/plain\r\n\r\nhello WALLED_SENSITIVE\r\n--XB--\r\n")
    files, fields = parse_multipart(body, "multipart/form-data; boundary=XB")
    assert fields == ["uploads/abc"]
    assert files[0].filename == "a.txt" and files[0].data == b"hello WALLED_SENSITIVE"


def test_socketio_and_json():
    obj = socketio_payload('421["perplexity_ask","hi WALLED_SENSITIVE",{"mode":"x"}]')
    assert "hi WALLED_SENSITIVE" in json_strings(obj)
    assert "inner WALLED_SENSITIVE" in json_strings({"a": '{"b": "inner WALLED_SENSITIVE"}'})


# --------------------------------------------------------------------- css
def test_csp_rewrite_cases():
    css = build_css(["div.x"], "#123456")
    h = css_hash(css)
    assert h in rewrite_csp("default-src 'self'", css)
    assert h in rewrite_csp("style-src 'self' 'nonce-abc'", css)
    # unsafe-inline without nonce: must NOT add a hash (that would disable unsafe-inline)
    assert rewrite_csp("style-src 'self' 'unsafe-inline'", css) == "style-src 'self' 'unsafe-inline'"
    # style-src-elem takes precedence
    out = rewrite_csp("style-src 'self'; style-src-elem 'self'", css)
    assert out.endswith(h) and out.count(h) == 1
    assert rewrite_csp("script-src 'self'", css) == "script-src 'self'"
    assert "'none'" not in rewrite_csp("style-src 'none'", css)


def test_inject_html():
    out = inject_html("<html><head><title>x</title></head><body></body></html>", "a{}")
    assert '<style id="walled-dlp-style">a{}</style></head>' in out
    assert inject_html(out, "a{}") == out


def test_host_matching(cfg):
    assert host_matches("sdmntprwestus.oaiusercontent.com", "*.oaiusercontent.com")
    assert cfg.is_upload_host("files.oaiusercontent.com")
    assert cfg.site_for_host("chatgpt.com").label == "ChatGPT"
    assert cfg.site_for_host("www.perplexity.ai").label == "Perplexity"
    assert cfg.site_for_host("evil-chatgpt.com") is None
    assert cfg.site_for_host("chatgpt.com").is_prompt_path("/backend-api/f/conversation")
    assert not cfg.site_for_host("chatgpt.com").is_prompt_path("/backend-api/f/conversation/prepare")


def test_browser_guard_detects_proxy_extension(tmp_path):
    import json as _j
    from walled_dlp.browser_guard import find_proxy_overrides
    root = tmp_path / "Chrome"
    prof = root / "Profile 3"
    (prof / "Extensions" / "eppio" / "1.0" / "_locales" / "en").mkdir(parents=True)
    (prof / "Extensions" / "eppio" / "1.0" / "_locales" / "en" / "messages.json").write_text(
        _j.dumps({"appName": {"message": "Urban VPN Proxy"}}))
    (root / "Local State").write_text(_j.dumps({"profile": {"info_cache": {"Profile 3": {"name": "Work"}}}}))
    (prof / "Secure Preferences").write_text(_j.dumps({"extensions": {"settings": {
        "eppio": {"state": 1, "manifest": {"name": "__MSG_appName__"},
                  "preferences": {"proxy": {"mode": "direct"}}},
        "other": {"state": 1, "manifest": {"name": "Adblock"}},
        "off": {"state": 0, "manifest": {"name": "Hide My IP"}, "preferences": {"proxy": {"mode": "fixed_servers"}}},
    }}}))
    found = find_proxy_overrides({"Chrome": root})
    assert [str(f) for f in found] == ["Urban VPN Proxy (Chrome › Work [Profile 3])"]
