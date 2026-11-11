"""Per-span visibility: is this text actually drawn where a human reader can see it?

Approach ("render differential"): render every page twice, once as-is and once with all text
removed (text-only redaction, images and vector graphics kept). A span a human can see changes the
pixels inside its box; a span that is white-on-white, covered by a shape or image, clipped away,
transparent, or drawn in an invisible render mode does not. On top of that, a few cheap
metadata rules (render mode, opacity, size, page bounds) explain *why* a span is hidden.

Coordinates: texttrace / rawdict boxes are in unrotated page space; pixmaps are rendered in
rotated space, so boxes go through page.rotation_matrix before indexing pixels.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

import numpy as np
import pymupdf

from ..findings import Finding, clip

INK_DELTA = 16          # per-channel difference (0..255) that counts as "this pixel was painted"
MIN_INK = 0.004         # fraction of inked pixels below which a span is treated as not drawn
HIDDEN_CONTRAST = 1.15  # WCAG contrast ratio below which text is unreadable (e.g. #F2F2F2 on white)
FAINT_CONTRAST = 1.5    # below this, text is very hard to see (#D0D0D0 on white); flagged, dropped
MIN_HEIGHT = 1.5        # points; glyphs shorter than this are not legible at any normal zoom
MIN_ADVANCE = 0.3       # points per character; catches horizontal squashing (Tz 1)
SCAN_IMAGE_COVER = 0.5  # an image covering this share of the page makes it a scan
FRAGMENT_ALNUM = 40     # hidden groups shorter than this (letters+digits) are "medium", longer are "high"

OCCLUDERS = ("fill-path", "fill-image", "fill-shade", "fill-imgmask")


def _rgb(color) -> tuple[float, float, float]:
    if color is None:
        return (0.0, 0.0, 0.0)
    c = tuple(color)
    if len(c) == 1:
        return (c[0],) * 3
    if len(c) == 3:
        return c
    if len(c) == 4:
        cy, m, y, k = c
        return ((1 - cy) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k))
    return (0.0, 0.0, 0.0)


def _lum(rgb) -> float:
    def ch(v):
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(float(v)) for v in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b) -> float:
    la, lb = _lum(a), _lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _pix(page, zoom) -> np.ndarray:
    pm = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom), alpha=False, colorspace=pymupdf.csRGB, annots=False)
    return np.frombuffer(pm.samples, dtype=np.uint8).reshape(pm.height, pm.width, pm.n)[:, :, :3].astype(np.int16)


def strip_text(doc) -> "pymupdf.Document":
    """A copy of the document with every text object removed, all other content intact."""
    bare = pymupdf.open("pdf", doc.tobytes())
    for p in bare:
        p.add_redact_annot(p.rect * p.derotation_matrix)
        p.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_NONE,
                           graphics=pymupdf.PDF_REDACT_LINE_ART_NONE,
                           text=pymupdf.PDF_REDACT_TEXT_REMOVE)
    return bare


@dataclass
class PageResult:
    findings: list[Finding] = field(default_factory=list)
    safe_text: str = ""
    raw_text: str = ""
    hidden_text: str = ""
    spans: int = 0
    hidden_spans: int = 0
    ocr_layer_spans: int = 0
    ocr_layer_text: str = ""


def _share_missing(s, extracted: set) -> float:
    chars = [(c[2], chr(c[0])) for c in s["chars"] if chr(c[0]).strip()]
    if not chars:
        return 0.0
    return sum(_key(o, c) not in extracted for o, c in chars) / len(chars)


def _span_text(s) -> str:
    return "".join(chr(c[0]) for c in s["chars"])


def _key(origin, ch) -> tuple:
    # ligatures: the tracer reports "ﬁ" as one char, the extractor as "f" + "i" at the same origin
    if len(ch) == 1 and ord(ch) >= 0xFB00:
        ch = unicodedata.normalize("NFKC", ch)[:1] or ch
    return (round(origin[0], 1), round(origin[1], 1), ch)


def analyze_page(page, bare_page, pno: int, zoom: float = 2.0, drop_faint: bool = True) -> PageResult:
    res = PageResult(raw_text=page.get_text())
    trace = page.get_texttrace()
    res.spans = len(trace)
    if not trace:
        return res

    w, h = page.cropbox.width, page.cropbox.height
    unrot = pymupdf.Rect(0, 0, w, h)
    rot = page.rotation_matrix
    full, bare = _pix(page, zoom), _pix(bare_page, zoom)
    H, W = full.shape[:2]

    log = page.get_bboxlog()
    images = [pymupdf.Rect(r) for t, r in log if t in ("fill-image", "fill-imgmask")]
    img_cover = max((r & unrot).get_area() for r in images) / unrot.get_area() if images else 0.0
    is_scan = img_cover >= SCAN_IMAGE_COVER

    def occluded(seq: int, box: pymupdf.Rect) -> bool:
        a = box.get_area()
        if a <= 0:
            return False
        for t, r in log[seq + 1:]:
            if t in OCCLUDERS and (pymupdf.Rect(r) & box).get_area() >= 0.8 * a:
                return True
        return False

    hidden_keys: set = set()
    groups: dict[tuple, list] = {}      # (severity, reason) -> [(bbox, text)]
    # MuPDF's extractor drops characters outside the active clip path (and the page); the tracer keeps
    # them. A span the tracer reports but the extractor does not is not drawn.
    extracted = {_key(c["origin"], c["c"]) for b in page.get_text("rawdict")["blocks"] if b.get("type") == 0
                 for ln in b["lines"] for sp in ln["spans"] for c in sp["chars"]}

    for s in trace:
        text = _span_text(s)
        if not text.strip():
            continue
        box = pymupdf.Rect(s["bbox"])
        reason = None
        severity = "high"
        if s["type"] == 3:
            if is_scan and any((box & r).get_area() > 0 for r in images):
                res.ocr_layer_spans += 1
                res.ocr_layer_text += text + " "
                continue
            reason = "invisible_render_mode"
        elif s.get("opacity", 1.0) < 0.05:
            reason = "transparent"
        elif not unrot.contains(pymupdf.Point((box.x0 + box.x1) / 2, (box.y0 + box.y1) / 2)) or (
                box.get_area() > 0 and (box & unrot).get_area() < 0.5 * box.get_area()):
            reason = "off_page"
        elif box.height < MIN_HEIGHT or box.width / max(1, len(text)) < MIN_ADVANCE:
            reason = "tiny"
        elif _share_missing(s, extracted) > 0.5:
            reason = "clipped"
        else:
            px = (box * rot) * pymupdf.Matrix(zoom, zoom)
            dy = px.height * 0.2
            x0, x1 = max(0, int(px.x0)), min(W, int(np.ceil(px.x1)))
            y0, y1 = max(0, int(px.y0 + dy)), min(H, int(np.ceil(px.y1 - dy)))
            if x1 - x0 < 1 or y1 - y0 < 1:
                reason = "tiny"
            else:
                F, B = full[y0:y1, x0:x1], bare[y0:y1, x0:x1]
                ink = (np.abs(F - B).max(axis=2) >= INK_DELTA).mean()
                bg = np.median(B.reshape(-1, 3), axis=0) / 255.0
                c = contrast(_rgb(s.get("color")), bg)
                if ink < MIN_INK:
                    if occluded(s["seqno"], box):
                        reason = "covered"
                    elif c < HIDDEN_CONTRAST:
                        reason = "low_contrast"
                    else:
                        reason = "not_rendered"
                elif c < HIDDEN_CONTRAST:
                    reason = "low_contrast"
                elif c < FAINT_CONTRAST:
                    reason, severity = "faint", "medium"
                    if not drop_faint:
                        groups.setdefault((severity, reason), []).append((box, text))
                        continue
        if reason is None:
            continue
        res.hidden_spans += 1
        for c in s["chars"]:
            hidden_keys.add(_key(c[2], chr(c[0])))
        groups.setdefault((severity, reason), []).append((box, text))

    for (severity, reason), items in groups.items():
        text = " ".join(t for _, t in items)
        n_alnum = sum(ch.isalnum() for ch in text)
        if n_alnum < 3:
            continue
        if n_alnum < FRAGMENT_ALNUM and severity == "high":
            severity = "medium"     # stray fragment (e.g. a footer pushed past the trim box): warn, still dropped
        union = pymupdf.Rect(items[0][0])
        for b, _ in items[1:]:
            union |= b
        if reason == "faint":
            check, msg = "faint_text", f"{len(items)} text span(s) with near-background colour"
            res.hidden_text += text + "\n"
        else:
            check, msg = "hidden_text", f"hidden text ({reason}): {len(items)} text span(s) a parser extracts but a reader cannot see"
            res.hidden_text += text + "\n"
        res.findings.append(Finding(check=check, severity=severity, page=pno, bbox=tuple(union), reason=reason,
                                    text=clip(text), message=msg))

    res.safe_text = _rebuild(page, hidden_keys) if hidden_keys else res.raw_text
    return res


def _rebuild(page, hidden: set) -> str:
    """Page text in PyMuPDF's reading order, minus the hidden characters."""
    out = []
    for b in page.get_text("rawdict")["blocks"]:
        if b.get("type") != 0:
            continue
        lines = []
        for ln in b["lines"]:
            s = "".join(c["c"] for sp in ln["spans"] for c in sp["chars"] if _key(c["origin"], c["c"]) not in hidden)
            if s.strip():
                lines.append(s)
        if lines:
            out.append("\n".join(lines))
    return "\n".join(out) + ("\n" if out else "")
