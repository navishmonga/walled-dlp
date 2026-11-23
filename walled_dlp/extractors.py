"""Turn request bodies into text that the detector can scan.

Supports: JSON prompt bodies, multipart/form-data uploads, raw file uploads,
plain text, PDF (text layer + OCR of rendered pages), images (OCR) and, as a
bonus, Office Open XML files (docx/xlsx/pptx).

OCR engine order: macOS Vision framework (built in, fast, no install) ->
Tesseract CLI if present. If neither is available an image can't be inspected
and the caller applies the `on_inspection_error` policy.
"""
from __future__ import annotations

import io
import json
import logging
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import HTTP

from .detector import Detector, Match

log = logging.getLogger("walled_dlp.extract")

IMAGE_MAGIC = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"BM": "image/bmp",
    b"II*\x00": "image/tiff",
    b"MM\x00*": "image/tiff",
}


class InspectionError(Exception):
    """Content could not be inspected (OCR missing, corrupt file, too large...)."""


@dataclass
class FileScan:
    filename: str
    kind: str
    match: Match
    error: str | None = None


@dataclass
class UploadedFile:
    filename: str
    content_type: str
    data: bytes


# --------------------------------------------------------------------------
# Sniffing
# --------------------------------------------------------------------------
def sniff_kind(data: bytes, content_type: str = "", filename: str = "") -> str:
    ct = (content_type or "").split(";")[0].strip().lower()
    name = (filename or "").lower()
    head = data[:16]
    if head.startswith(b"%PDF") or ct == "application/pdf" or name.endswith(".pdf"):
        return "pdf"
    for magic in IMAGE_MAGIC:
        if head.startswith(magic):
            return "image"
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image"
    if data[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1", b"ftypavif"):
        return "image"
    if ct.startswith("image/") or re.search(r"\.(png|jpe?g|gif|webp|bmp|tiff?|heic|avif)$", name):
        return "image"
    if head.startswith(b"PK\x03\x04") and re.search(r"\.(docx|xlsx|pptx)$", name or "x.docx"):
        return "office"
    if ct.startswith("text/") or ct in ("application/json", "application/xml", "application/csv"):
        return "text"
    if _looks_textual(data):
        return "text"
    return "binary"


def _looks_textual(data: bytes) -> bool:
    sample = data[:4096]
    if not sample:
        return True
    if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        # tolerate a multibyte char cut at the end of the sample
        return e.start > len(sample) - 4


def decode_text(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="ignore")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="ignore")


# --------------------------------------------------------------------------
# OCR
# --------------------------------------------------------------------------
_vision_ok: bool | None = None


def _ocr_vision(image_bytes: bytes) -> str:
    import Vision  # type: ignore  (pyobjc-framework-Vision)
    from Foundation import NSData  # type: ignore

    ns = NSData.dataWithBytes_length_(image_bytes, len(image_bytes))
    handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(ns, None)
    req = Vision.VNRecognizeTextRequest.alloc().init()
    req.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
    req.setUsesLanguageCorrection_(False)
    ok, err = handler.performRequests_error_([req], None)
    if not ok:
        raise InspectionError(f"Vision OCR failed: {err}")
    lines = []
    for obs in req.results() or []:
        cands = obs.topCandidates_(1)
        if cands and len(cands):
            lines.append(str(cands[0].string()))
    return "\n".join(lines)


def _to_png(image_bytes: bytes, upscale_small: bool = True) -> bytes:
    from PIL import Image, ImageOps

    img = Image.open(io.BytesIO(image_bytes))
    img = ImageOps.exif_transpose(img)
    if getattr(img, "n_frames", 1) > 1:
        img.seek(0)
    img = img.convert("L")
    if upscale_small and max(img.size) < 1600:
        f = 2 if max(img.size) >= 800 else 3
        img = img.resize((img.width * f, img.height * f))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _ocr_tesseract(image_bytes: bytes) -> str:
    exe = shutil.which("tesseract")
    if not exe:
        for cand in ("/opt/homebrew/bin/tesseract", "/usr/local/bin/tesseract",
                     r"C:\Program Files\Tesseract-OCR\tesseract.exe"):
            if shutil.which(cand) or __import__("os").path.exists(cand):
                exe = cand
                break
    if not exe:
        raise InspectionError("No OCR engine available (install Tesseract or run on macOS)")
    png = _to_png(image_bytes)
    out = subprocess.run([exe, "stdin", "stdout", "--psm", "3"], input=png,
                         capture_output=True, timeout=60)
    if out.returncode != 0:
        raise InspectionError("tesseract failed: " + out.stderr.decode(errors="ignore")[:200])
    return out.stdout.decode("utf-8", errors="ignore")


def ocr_image(image_bytes: bytes) -> str:
    global _vision_ok
    if sys.platform == "darwin" and _vision_ok is not False:
        try:
            text = _ocr_vision(image_bytes)
            _vision_ok = True
            return text
        except ImportError:
            _vision_ok = False
            log.warning("pyobjc Vision not installed; falling back to tesseract")
        except InspectionError:
            raise
        except Exception as e:  # pragma: no cover - platform specific
            log.warning("Vision OCR error %s; falling back to tesseract", e)
    return _ocr_tesseract(image_bytes)


# --------------------------------------------------------------------------
# Format-specific scanners
# --------------------------------------------------------------------------
def scan_pdf(data: bytes, det: Detector, max_ocr_pages: int = 25) -> Match:
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception as e:
                raise InspectionError(f"encrypted PDF: {e}")
        texts = []
        for page in reader.pages:
            try:
                texts.append(page.extract_text() or "")
            except Exception as e:  # damaged page: keep going
                log.debug("pdf page text error: %s", e)
        # Metadata (title/subject/keywords) can also carry the marker.
        meta = reader.metadata or {}
        texts.extend(str(v) for v in meta.values() if v)
    except InspectionError:
        raise
    except Exception as e:
        raise InspectionError(f"unreadable PDF: {e}")

    m = det.scan("\n".join(texts), fuzzy=False)
    if m.found:
        return m
    # No hit in the text layer: the marker may be in a scanned page or an
    # embedded image, so render pages and OCR them.
    return _ocr_pdf(data, det, max_ocr_pages)


def _ocr_pdf(data: bytes, det: Detector, max_pages: int) -> Match:
    try:
        import pypdfium2 as pdfium
    except ImportError:
        raise InspectionError("pypdfium2 not installed; cannot OCR PDF")
    pdf = pdfium.PdfDocument(data)
    try:
        n = len(pdf)
        if n > max_pages:
            log.info("PDF has %d pages; OCR limited to first %d", n, max_pages)
        for i in range(min(n, max_pages)):
            page = pdf[i]
            pil = page.render(scale=2.0).to_pil()
            buf = io.BytesIO()
            pil.save(buf, "PNG")
            m = det.scan(ocr_image(buf.getvalue()), fuzzy=True)
            if m.found:
                return m
        if n > max_pages:
            raise InspectionError(f"PDF has {n} pages; only {max_pages} were OCR-checked")
        return Match(False)
    finally:
        pdf.close()


def scan_office(data: bytes, det: Detector) -> Match:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise InspectionError(f"bad office file: {e}")
    parts = []
    for name in z.namelist():
        if name.endswith(".xml") and not name.startswith("[Content_Types]"):
            raw = z.read(name).decode("utf-8", errors="ignore")
            parts.append(re.sub(r"<[^>]+>", "", re.sub(r"</w:p>|</a:p>|</si>", "\n", raw)))
    return det.scan("\n".join(parts))


def scan_file(f: UploadedFile, det: Detector, max_bytes: int, max_ocr_pages: int) -> FileScan:
    kind = sniff_kind(f.data, f.content_type, f.filename)
    if len(f.data) > max_bytes:
        return FileScan(f.filename, kind, Match(False), f"file too large to inspect ({len(f.data)} bytes)")
    try:
        if kind == "pdf":
            m = scan_pdf(f.data, det, max_ocr_pages)
        elif kind == "image":
            m = det.scan(ocr_image(f.data), fuzzy=True)
        elif kind == "office":
            m = scan_office(f.data, det)
        elif kind == "text":
            m = det.scan(decode_text(f.data))
        else:
            # Unknown binary: cheap best-effort scan of any embedded text.
            m = det.scan(f.data.decode("latin-1", errors="ignore"))
            if not m.found:
                m = det.scan(f.data.decode("utf-16-le", errors="ignore"))
        return FileScan(f.filename, kind, m)
    except InspectionError as e:
        return FileScan(f.filename, kind, Match(False), str(e))
    except Exception as e:  # never let a parser bug let content through silently
        log.exception("extractor crashed")
        return FileScan(f.filename, kind, Match(False), f"extractor error: {e}")


# --------------------------------------------------------------------------
# Body parsing
# --------------------------------------------------------------------------
def parse_multipart(body: bytes, content_type: str) -> tuple[list[UploadedFile], list[str]]:
    """Return (files, plain_field_values)."""
    msg = BytesParser(policy=HTTP).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    files: list[UploadedFile] = []
    fields: list[str] = []
    if not msg.is_multipart():
        return files, fields
    for part in msg.iter_parts():
        payload = part.get_payload(decode=True) or b""
        fname = part.get_filename()
        if fname is not None:
            files.append(UploadedFile(fname, part.get_content_type(), payload))
        else:
            fields.append(decode_text(payload))
    return files, fields


def json_strings(obj, out: list[str] | None = None) -> list[str]:
    """Collect every string (keys and values) in a JSON document."""
    if out is None:
        out = []
    if isinstance(obj, str):
        out.append(obj)
        # Some APIs double-encode JSON inside a string field.
        s = obj.strip()
        if len(s) > 1 and s[0] in "{[" and s[-1] in "}]":
            try:
                json_strings(json.loads(s), out)
            except ValueError:
                pass
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            json_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            json_strings(v, out)
    return out


def try_parse_json(body: bytes):
    s = body.strip()
    if not s or s[:1] not in (b"{", b"["):
        return None
    try:
        return json.loads(decode_text(s))
    except ValueError:
        return None


def socketio_payload(text: str):
    """Socket.IO frames look like `42["event",{...}]`; return the JSON part."""
    m = re.match(r"^\d+(?:/[^,]*,)?\d*(\[.*|\{.*)$", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except ValueError:
        return None
