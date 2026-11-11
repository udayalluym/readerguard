"""Optional OCR cross-check: does the text layer say what the page *looks* like?

Catches attacks no text-layer rule can see: a remapped font (ToUnicode) whose glyphs show one word
while extraction yields another, and fake invisible "OCR layers" placed over scanned images.

Backends: Apple Vision via `ocrmac` (macOS), or any callable `fn(png_bytes) -> str` you pass in.
"""
from __future__ import annotations

import io

from .findings import Finding, clip
from .textscan import tokens

MIN_TOKENS = 15          # skip pages with too little text to judge
MIN_AGREEMENT = 0.5      # share of text-layer tokens that OCR must also find


def default_backend(boxes: bool = False):
    """fn(png) -> str, or with boxes=True fn(png) -> [(text, confidence, (x0, y0, x1, y1) normalised)]."""
    try:
        from ocrmac import ocrmac
    except ImportError:
        return None
    from PIL import Image

    def lines(png: bytes):
        img = Image.open(io.BytesIO(png))
        out = []
        for text, conf, (x, y, w, h) in ocrmac.OCR(img, recognition_level="accurate").recognize():
            out.append((text, conf, (x, 1 - y - h, x + w, 1 - y)))
        return out

    if boxes:
        return lines
    return lambda png: "\n".join(t for t, _, _ in lines(png))


def ocr_png(png: bytes, fn=None) -> str | None:
    fn = fn or default_backend()
    return fn(png) if fn else None


def ocr_page(page, fn, dpi: int = 200) -> str:
    return fn(page.get_pixmap(dpi=dpi, annots=False).tobytes("png"))


def ocr_findings(page, pno: int, layer_text: str, fn, label: str) -> list[Finding]:
    want = tokens(layer_text)
    if len(want) < MIN_TOKENS:
        return []
    got = set(tokens(ocr_page(page, fn)))
    agree = sum(t in got for t in want) / len(want)
    if agree >= MIN_AGREEMENT:
        return []
    missing = " ".join(t for t in want if t not in got)
    return [Finding(check="visual_mismatch", severity="high", page=pno, reason=label, text=clip(missing),
                    message=f"only {agree:.0%} of the {label.replace('_', ' ')} matches what OCR reads on the "
                            "rendered page (remapped font or fake OCR layer)")]
