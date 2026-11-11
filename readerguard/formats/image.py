"""Raster images (PNG, JPEG, GIF, WebP, BMP, TIFF).

- Payload smuggling: data appended after the image end marker, other file formats embedded (polyglots),
  script in metadata.
- Side-channel text: EXIF / XMP / PNG text chunks / JPEG comments.
- Hidden text for vision models: content painted into fully transparent pixels, and near-background text
  that only appears after contrast enhancement (needs an OCR backend). Visible text is OCR'd and checked
  for injection phrasing.
"""
from __future__ import annotations

import difflib
import io
import re
import struct

import numpy as np

from .. import ocr as ocrmod
from .. import textscan
from ..content import content_findings, hidden_text_finding
from ..findings import Finding, Report, clip

MAX_PIXELS = 120_000_000
SIGNATURES = [(rb"<script", "HTML script"), (rb"<\?php", "PHP code"), (rb"<html", "HTML document"),
              (rb"%PDF-", "PDF document"), (rb"PK\x03\x04", "ZIP archive"), (rb"MZ\x90\x00", "Windows executable"),
              (rb"\x7fELF", "Linux executable"), (rb"<svg", "SVG document"), (rb"#!/bin/", "shell script")]
EXIF_TEXT = {270: "ImageDescription", 315: "Artist", 33432: "Copyright", 305: "Software", 0x9C9B: "XPTitle",
             0x9C9C: "XPComment", 0x9C9D: "XPAuthor", 0x9C9E: "XPKeywords", 0x9C9F: "XPSubject"}


def _png_end(raw: bytes):
    i = 8
    while i + 8 <= len(raw):
        n, typ = struct.unpack(">I4s", raw[i:i + 8])
        i += 12 + n
        if typ == b"IEND":
            return i
    return None


def _jpeg_end(raw: bytes):
    i = 2
    while i + 4 <= len(raw):
        if raw[i] != 0xFF:
            return None
        m = raw[i + 1]
        if m == 0xD9:
            return i + 2
        if m in (0x01,) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        seg = struct.unpack(">H", raw[i + 2:i + 4])[0]
        i += 2 + seg
        if m == 0xDA:                       # start of scan: skip entropy-coded data
            while i + 1 < len(raw):
                if raw[i] == 0xFF and raw[i + 1] != 0x00 and not (0xD0 <= raw[i + 1] <= 0xD7):
                    break
                i += 1
    return None


def scan_image(raw: bytes, name: str = "<bytes>", *, ocr_check: bool | str = "auto", ocr_fn=None) -> Report:
    from PIL import Image, ImageOps

    rep = Report(path=name, format="image", pages=1)
    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        im = Image.open(io.BytesIO(raw))
        im.verify()
        im = Image.open(io.BytesIO(raw))
        im.load()
    except Image.DecompressionBombError:
        rep.findings.append(Finding(check="decompression_bomb", severity="high",
                                    message="image dimensions exceed the safety limit (decompression bomb)"))
        return rep
    except Exception as e:
        rep.error = f"cannot decode image: {type(e).__name__}"
        rep.findings.append(Finding(check="malformed_image", severity="high", message=rep.error))
        return rep
    rep.format = f"image/{(im.format or 'unknown').lower()}"

    # ---- appended data and polyglots
    end = _png_end(raw) if im.format == "PNG" else _jpeg_end(raw) if im.format == "JPEG" else None
    if end is not None and len(raw) - end > 16:
        tail = raw[end:]
        kinds = [k for sig, k in SIGNATURES if re.search(sig, tail[:5_000_000], re.I)]
        rep.findings.append(Finding(
            check="appended_data", severity="critical" if kinds else "medium",
            reason=", ".join(kinds) or None,
            message=f"{len(tail)} bytes after the end of the image" + (f" containing a {kinds[0]}" if kinds else "")))
    else:
        body = raw[64:]
        kinds = [k for sig, k in SIGNATURES[:4] + SIGNATURES[5:7] if re.search(sig, body[:20_000_000], re.I)]
        if kinds:
            rep.findings.append(Finding(check="polyglot", severity="high", reason=", ".join(kinds),
                                        message=f"image bytes embed a {kinds[0]}"))

    # ---- metadata text
    meta = []
    for k, v in (im.info or {}).items():
        if isinstance(v, bytes):
            v = v.decode("utf-8", "ignore")
        if isinstance(v, str) and k not in ("icc_profile", "exif"):
            meta.append((f"metadata.{k}", v))
    try:
        exif = im.getexif()
        for tag, label in EXIF_TEXT.items():
            v = exif.get(tag)
            if v:
                v = v.decode("utf-16-le", "ignore") if isinstance(v, bytes) and tag >= 0x9C9B else v
                meta.append((f"exif.{label}", v if isinstance(v, str) else str(v)))
        uc = exif.get_ifd(0x8769).get(0x9286)
        if uc:
            meta.append(("exif.UserComment", uc[8:].decode("utf-16-le" if uc[:8].startswith(b"UNICODE") else "utf-8",
                                                          "ignore") if isinstance(uc, bytes) else str(uc)))
    except Exception:
        pass
    for ch, v in meta:
        v = v.replace("\x00", "")
        if re.search(r"<script|javascript:|on\w+\s*=", v, re.I):
            rep.findings.append(Finding(check="metadata_script", severity="high", reason=ch, text=clip(v, 100),
                                        message=f"script markup in {ch} (stored XSS if displayed)"))
        long_ = sum(c.isalnum() for c in v) >= 40 and ch not in ("metadata.parameters", "metadata.xmp",
                                                                   "metadata.XML:com.adobe.xmp")
        rep.findings += content_findings(v, ch, hidden=True, side_channel="low" if long_ else None)

    # ---- pixels
    rgba = im.convert("RGBA") if im.mode in ("RGBA", "LA", "PA") or (im.mode == "P" and "transparency" in im.info) else None
    if rgba is not None:
        a = np.asarray(rgba)
        clear = a[..., 3] == 0
        if clear.mean() > 0.01:
            rgb = a[..., :3][clear].astype(np.int16)
            spread = rgb.std(axis=0).max() if len(rgb) > 50 else 0
            if spread > 25:
                rep.findings.append(Finding(check="hidden_pixels", severity="medium", reason="transparent_pixels",
                                            message="fully transparent pixels carry image content that a model "
                                                    "reading raw RGB can see"))

    box_fn = None if ocr_fn else (ocrmod.default_backend(boxes=True) if ocr_check else None)
    fn = ocr_fn or (ocrmod.default_backend() if ocr_check else None)
    if fn is None:
        rep.findings.append(Finding(check="ocr_unavailable", severity="info",
                                    message="no OCR backend: text inside the image was not checked"))
        return rep
    shown = im.convert("RGBA") if rgba is not None else im.convert("RGB")
    if rgba is not None:
        white = Image.new("RGBA", shown.size, (255, 255, 255, 255))
        shown = Image.alpha_composite(white, shown).convert("RGB")
    enhanced = ImageOps.equalize(ImageOps.autocontrast(shown.convert("L"), cutoff=0))
    variants = [_png(enhanced)] + ([_png(im.convert("RGB"))] if rgba is not None else [])

    if box_fn:
        vis = box_fn(_png(shown))
        visible = "\n".join(t for t, _, _ in vis)
        hidden_lines = []
        for v in variants:
            for t, conf, b in box_fn(v):
                if conf >= 0.4 and sum(c.isalnum() for c in t) >= 8 and not any(_overlap(b, vb) > 0.25 for _, _, vb in vis):
                    hidden_lines.append(t)
        hidden = " ".join(dict.fromkeys(hidden_lines))
        enough = sum(c.isalnum() for c in hidden) >= 15
    else:   # text-only backend: fall back to words that OCR finds only after enhancement
        visible = fn(_png(shown)) or ""
        extra_text = " ".join(fn(v) or "" for v in variants)
        seen = set(textscan.tokens(visible))
        extra = [t for t in textscan.tokens(extra_text) if t not in seen and t.isalpha() and len(t) >= 4
                 and not difflib.get_close_matches(t, seen, n=1, cutoff=0.75)]
        hidden = " ".join(dict.fromkeys(extra))
        enough = len(set(extra)) >= 5
    if enough:
        rep.findings += hidden_text_finding(hidden, "the image", "low_contrast_or_transparent")
        rep.findings += content_findings(hidden, "hidden image text", hidden=True)
    rep.safe_pages = [visible]
    rep.raw_pages = [visible + "\n" + hidden]
    rep.findings += content_findings(visible, "text in image", hidden=False)
    return rep


def _overlap(a, b) -> float:
    ix = max(0.0, min(a[2], b[2]) - max(a[0], b[0]))
    iy = max(0.0, min(a[3], b[3]) - max(a[1], b[1]))
    area = min((a[2] - a[0]) * (a[3] - a[1]), (b[2] - b[0]) * (b[3] - b[1]))
    return ix * iy / area if area > 0 else 0.0


def _png(im) -> bytes:
    if max(im.size) > 3000:
        im = im.copy()
        im.thumbnail((3000, 3000))
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()
