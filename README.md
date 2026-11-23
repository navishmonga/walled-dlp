# WALLED DLP

A lightweight **standalone desktop DLP app** for the ChatGPT and Perplexity web apps.
It needs no browser extension, plugin or add-on.

* Checks **text prompts** and **file uploads** (text, PDF, images, plus docx/xlsx/pptx) for the marker `WALLED_SENSITIVE`.
* When the marker is found, it holds the request and shows a **native Continue / Cancel dialog**. Nothing leaves the machine until you choose.
* **Recolours AI-generated responses** on both sites (green `#0a7d32` by default).

## How it works

```
Browser ──(PAC: only AI domains)──► WALLED DLP (127.0.0.1:8765, local HTTPS proxy)
                                     ├─ holds every POST/PUT/WebSocket msg to target hosts
                                     ├─ extracts text: JSON · multipart · PDF · OCR (macOS Vision)
                                     ├─ WALLED_SENSITIVE? → native dialog → forward or 403
                                     └─ injects <style> into ChatGPT/Perplexity HTML (+ CSP hash)
                                           ▼
                        chatgpt.com · perplexity.ai · upload storage
```

The app changes only OS settings, never the browser itself:

1. **Proxy auto-config (PAC).** Only `chatgpt.com`, `perplexity.ai` and their upload-storage hosts are routed to the app. All other traffic goes direct and is never touched. Your previous proxy settings are saved and restored when the app quits.
2. **Per-machine root CA with X.509 name constraints.** The key is generated locally and stays on this machine. The certificate is only valid for the domains above, so even if the key leaked it could not impersonate any other site.

| Request type | What happens if the marker is found |
|---|---|
| Prompt endpoint (e.g. `POST /backend-api/f/conversation`, `/rest/sse/perplexity_ask`) | Native dialog |
| File upload (multipart, or a raw PUT to upload storage) | Native dialog |
| Anything else on those hosts (typing previews, telemetry, autosuggest) | Blocked silently, unless you already chose Continue for the same text |
| Same content you cancelled in the last few seconds | Blocked again without a second dialog |
| File that can't be inspected (OCR missing, encrypted PDF, too large) | Dialog: "could not be inspected" (`on_inspection_error`) |

The app **fails closed**: if the dialog errors out or times out (60 s), the request is cancelled.

## Install (macOS, Apple Silicon or Intel)

Requires Python 3.12 or newer (`brew install python@3.12`).

```bash
cd ~/Desktop/WalledDLP
chmod +x install.sh run.sh packaging/build_app.sh
./install.sh                # creates .venv, installs deps, generates + trusts the CA (asks for your password)
./run.sh                    # 🛡 DLP icon appears in the menu bar
```

Then **quit and reopen your browser once** so it picks up the certificate and the proxy setting.

* Start at login: `./install.sh --autostart`, which installs a LaunchAgent that restarts the app if it crashes.
* Build a double-clickable menu-bar app: `./packaging/build_app.sh` → `dist/WalledDLP.app`
* Remove everything: `.venv/bin/python -m walled_dlp uninstall` (restores proxy settings, removes the CA and autostart)

## Try it

```bash
.venv/bin/python -m walled_dlp test-dialog                 # shows the native dialog
.venv/bin/python scripts/make_fixtures.py                  # sample files in tests/fixtures
.venv/bin/python -m walled_dlp scan tests/fixtures/*       # detection + OCR check (uses macOS Vision)
.venv/bin/python -m walled_dlp status
```

In the browser:

1. Type `test WALLED_SENSITIVE` into ChatGPT or Perplexity and send it. The dialog appears.
   * **Cancel**: the site shows a send error and nothing is transmitted.
   * **Continue**: the message is sent normally.
2. Upload `tests/fixtures/marker_scanned.pdf` or `marker.png`. The dialog appears before the file is uploaded.
3. AI answers appear in green. To turn this off, use the menu-bar toggle, then reload the page.

## Menu bar

The menu shows live counters and these items:

* **Pause/Resume protection**
* **Recolour AI responses**
* **Open audit log**: `~/Library/Logs/WalledDLP/audit.jsonl`, one JSON line per decision. Prompt and file contents are never logged.
* **Open config folder**: `~/Library/Application Support/WalledDLP`
* **Quit**: also restores your proxy settings.

## Configuration

Defaults are in `walled_dlp/config.default.json`. To change them, put overrides in `~/Library/Application Support/WalledDLP/config.json`, which is deep-merged over the defaults. For example:

```json
{
  "response_color": "#7b1fa2",
  "sites": { "chatgpt": { "prompt_paths": ["^/backend-api/(f/)?conversation/?$", "^/backend-api/new-send-path"] } },
  "dialog_timeout_seconds": 45,
  "on_inspection_error": "block"
}
```

ChatGPT and Perplexity change their APIs and markup from time to time. When something stops being caught, run `./run.sh --discover`. It logs every request to the target hosts (method, path, content type, size) in `~/Library/Logs/WalledDLP/walled-dlp.log`. Add the new path to `prompt_paths`, or the new selector to `response_selectors`. If you add a new upload host, regenerate the CA: `python -m walled_dlp setup --force`.

## Tests

```bash
.venv/bin/pip install pytest && .venv/bin/python -m pytest -q
```

The 39 tests cover:

* Detector evasion cases: zero-width characters, full-width characters, line wraps, OCR noise.
* Every fixture file: text, text PDF, wrapped PDF, scanned PDF, PNG.
* CSP rewriting rules.
* An end-to-end run of the real proxy engine between curl and a local upstream. This includes TLS interception with the name-constrained CA, cancel/continue for prompts and uploads, silent blocks, dedupe, HTML recolouring and the audit log.

## Known limitations / to verify on your Mac

* **Cloudflare:** both sites sit behind Cloudflare. If a site starts showing "verify you are human" loops while the app runs, Cloudflare is flagging the proxy's TLS fingerprint. The fix is a browser-impersonating upstream TLS client (planned).
* **Endpoints and selectors** are based on the sites' current behaviour. Confirm them with `--discover` on day one.
* **Chunked Azure uploads** (`?comp=block`, used only for very large files) are inspected chunk by chunk, so detection is best-effort for those.
* **Cancel UX:** Cancel happens at the network layer, so the page shows a send or upload error rather than a friendly message.
* **Firefox:** it must trust OS certificates. This is on by default in recent versions; otherwise set `security.enterprise_roots.enabled = true`.
* **Proxy/VPN browser extensions** (Urban VPN, Hide My IP and similar) override the system proxy, so that browser profile bypasses the app. WALLED DLP detects this: the menu-bar icon shows ⚠︎ with the extension's name, a notification appears, and `walled_dlp status` lists it. Disable the extension in `chrome://extensions`. In a fleet, block it with the Chrome policy `ExtensionSettings` → `{"*": {"blocked_permissions": ["proxy"]}}` plus `ProxyMode=system` via MDM.
* **Not covered:** the ChatGPT and Perplexity *desktop* apps, mobile apps, and browsers or VPNs configured to ignore the system proxy. In a managed fleet, lock the proxy settings with MDM.
* **Windows:** support is implemented (dialog, registry PAC, `certutil`) but untested. OCR on Windows needs Tesseract.
