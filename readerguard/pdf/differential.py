"""Parser differential: text that a *different* PDF parser extracts but that never reaches the screen.

PyMuPDF honours optional-content visibility and clip paths; pdfminer.six (behind pdfplumber,
unstructured, LangChain's PDFMinerLoader, ...) does not. Whatever pdfminer returns beyond the visible
text is content an attacker can aim at those pipelines.
"""
from __future__ import annotations

import io
import logging
from collections import Counter

logging.getLogger("pdfminer").setLevel(logging.ERROR)

from ..findings import Finding, clip
from ..textscan import tokens

MIN_EXTRA_TOKENS = 4      # distinct unseen tokens on one page before we report
MIN_EXTRA_SHARE = 0.02    # ...and at least this share of that page's pdfminer tokens


def available() -> bool:
    try:
        import pdfminer  # noqa: F401
        return True
    except ImportError:
        return False


def pdfminer_pages(raw: bytes) -> list[str]:
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LTTextContainer
    pages = []
    for layout in extract_pages(io.BytesIO(raw)):
        pages.append("".join(el.get_text() for el in layout if isinstance(el, LTTextContainer)))
    return pages


def differential_findings(raw: bytes, visible_pages: list[str], all_pages: list[str]) -> list[Finding]:
    """visible_pages: safe text; all_pages: everything PyMuPDF's tracer saw (incl. hidden spans)."""
    try:
        other = pdfminer_pages(raw)
    except Exception as e:  # malformed files: pdfminer is stricter than MuPDF
        return [Finding(check="parser_error", severity="low", message=f"pdfminer failed: {type(e).__name__}")]
    out = []
    for pno, text in enumerate(other):
        if pno >= len(visible_pages):
            break
        seen = set(tokens(visible_pages[pno])) | set(tokens(all_pages[pno]))
        mt = tokens(text)
        extra = Counter(t for t in mt if t not in seen)
        if len(extra) >= MIN_EXTRA_TOKENS and sum(extra.values()) >= MIN_EXTRA_SHARE * max(1, len(mt)):
            sample = " ".join(t for t in mt if t in extra)
            out.append(Finding(
                check="parser_differential", severity="high", page=pno, reason="pdfminer_only", text=clip(sample),
                message=f"{len(extra)} distinct words are extracted by pdfminer but are not drawn on the page "
                        "(hidden layer, clipped or off-page content)"))
    return out
