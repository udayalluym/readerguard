"""PDF: run every check and return a Report with findings and visible-only text."""
from __future__ import annotations

import pymupdf

from .. import ocr, textscan
from ..content import content_findings, novel_prose
from ..findings import Report
from . import differential, structure
from .visibility import analyze_page, strip_text

pymupdf.TOOLS.mupdf_display_errors(False)
META_PROSE = {"metadata.title", "metadata.subject", "metadata.keywords", "metadata.author"}


def scan_pdf(raw: bytes, name: str = "<bytes>", *, differential_check: bool = True, ocr_check: bool | str = "auto",
             ocr_fn=None, zoom: float = 2.0, drop_faint: bool = True, max_pages: int | None = None) -> Report:
    rep = Report(path=name, format="pdf")
    try:
        doc = pymupdf.open("pdf", raw)
    except Exception as e:
        rep.error = f"cannot open PDF: {e}"
        return rep
    if doc.needs_pass:
        rep.error = "encrypted PDF (password required), contents cannot be inspected"
        return rep
    rep.pages = doc.page_count
    fn = ocr_fn or (ocr.default_backend() if ocr_check else None)

    rep.findings += structure.structural_findings(doc, raw)
    bare = strip_text(doc)
    all_pages = []
    n = doc.page_count if max_pages is None else min(max_pages, doc.page_count)
    for pno in range(n):
        page = doc[pno]
        pr = analyze_page(page, bare[pno], pno, zoom=zoom, drop_faint=drop_faint)
        rep.findings += pr.findings
        rep.safe_pages.append(pr.safe_text)
        rep.raw_pages.append(pr.raw_text)
        all_pages.append(pr.raw_text + "\n" + pr.hidden_text)
        rep.findings += content_findings(pr.hidden_text, "hidden_text", pno, hidden=True)
        rep.findings += content_findings(pr.safe_text, "page_text", pno, hidden=False)
        if fn and pr.ocr_layer_spans:
            rep.findings += ocr.ocr_findings(page, pno, pr.ocr_layer_text, fn, "invisible_ocr_layer")
        elif fn and ocr_check is True:
            rep.findings += ocr.ocr_findings(page, pno, pr.safe_text, fn, "text_layer")

    body = set(textscan.tokens(" ".join(rep.safe_pages)))
    for channel, pno, text in structure.side_channel_texts(doc):
        side = None
        if channel.startswith(("annotation", "embedded_file.content", "form_field")):
            side = "high" if ".hidden" in channel else "low"
        rep.findings += content_findings(text, channel, pno, hidden=True, side_channel=side)
        if channel in META_PROSE:
            rep.findings += novel_prose(text, body, channel)

    if differential_check and differential.available():
        rep.findings += differential.differential_findings(raw, rep.safe_pages, all_pages)
    return rep
