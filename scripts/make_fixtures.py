"""Generate test files containing (or not containing) the marker.

    python scripts/make_fixtures.py [out_dir]

Creates: marker.txt, clean.txt, marker_text.pdf, marker_scanned.pdf,
marker.png, marker_wrapped.pdf, clean.pdf, clean.png, marker_zero_width.txt
"""
import io
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

MARK = "WALLED_SENSITIVE"


def font(size=44):
    for p in ("/System/Library/Fonts/Supplemental/Arial.ttf", "/Library/Fonts/Arial.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "C:/Windows/Fonts/arial.ttf"):
        if Path(p).exists():
            return ImageFont.truetype(p, size)
    return ImageFont.load_default(size=size)


def image_with(text: str, size=(1400, 500)) -> Image.Image:
    img = Image.new("RGB", size, "white")
    d = ImageDraw.Draw(img)
    y = 60
    for line in text.split("\n"):
        d.text((60, y), line, fill="black", font=font())
        y += 80
    return img


def text_pdf(lines: list[str]) -> bytes:
    """Minimal hand-written PDF with a real text layer (no extra deps)."""
    content = "BT /F1 18 Tf 72 720 Td 22 TL " + " ".join(
        "(" + l.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ") '" for l in lines
    ) + " ET"
    objs = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        "/Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n{o}\nendobj\n".encode("latin-1"))
    xref = out.tell()
    out.write(f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode())
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def main(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    (out / "marker.txt").write_text(f"Quarterly numbers\nInternal: {MARK}\nRevenue 12.4 Cr\n")
    (out / "clean.txt").write_text("Quarterly numbers\nRevenue 12.4 Cr\n")
    (out / "marker_zero_width.txt").write_text("Note: WALLED\u200b_SENSI\u200dTIVE do not share\n")
    (out / "marker_text.pdf").write_bytes(text_pdf(["Board pack", f"Classification: {MARK}", "Page 1"]))
    (out / "marker_wrapped.pdf").write_bytes(text_pdf(["Classification: WALLED_SEN-", "SITIVE (wrapped)"]))
    (out / "clean.pdf").write_bytes(text_pdf(["Board pack", "Nothing secret here"]))
    image_with(f"Screenshot of a spreadsheet\nTag: {MARK}\nTotal 42").save(out / "marker.png")
    image_with("Screenshot of a spreadsheet\nTotal 42").save(out / "clean.png")
    image_with(f"Scanned contract\n{MARK}\nSigned copy", (1275, 1650)).save(
        out / "marker_scanned.pdf", "PDF", resolution=150)
    print("fixtures written to", out)


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "tests" / "fixtures")
