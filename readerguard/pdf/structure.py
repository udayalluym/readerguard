"""Document-level checks: active content, side channels that carry text outside the page content,
and structural tricks (hidden layers, incremental updates)."""
from __future__ import annotations

import re

import pymupdf

from ..findings import Finding, clip

_ACTIVE = [
    (re.compile(rb"/(JS|JavaScript)\b"), "javascript", "high", "document contains JavaScript"),
    (re.compile(rb"/Launch\b"), "launch_action", "high", "document contains a Launch action (runs an external program)"),
    (re.compile(rb"/(SubmitForm|ImportData)\b"), "form_action", "medium", "document submits or imports form data"),
    (re.compile(rb"/RichMedia\b|/XFA\b"), "rich_content", "medium", "document contains RichMedia or XFA content"),
]


def side_channel_texts(doc) -> list[tuple[str, int | None, str]]:
    """(channel, page, text) for text that lives outside the page content stream.

    Many RAG loaders copy these into chunk text or metadata (titles, keywords, comments)."""
    out: list[tuple[str, int | None, str]] = []
    for k, v in (doc.metadata or {}).items():
        if v and k not in ("format", "encryption", "creationDate", "modDate"):
            out.append((f"metadata.{k}", None, str(v)))
    try:
        xmp = doc.get_xml_metadata()
    except Exception:
        xmp = ""
    if xmp:
        body = re.sub(r"<[^>]+>", " ", xmp)
        out.append(("xmp", None, body))
    for pno, page in enumerate(doc):
        for a in page.annots() or []:
            info = a.info or {}
            text = " ".join(x for x in (info.get("content"), info.get("title"), info.get("subject")) if x)
            if text.strip():
                hidden = bool(a.flags & (pymupdf.PDF_ANNOT_IS_HIDDEN | pymupdf.PDF_ANNOT_IS_NO_VIEW))
                out.append((f"annotation.{a.type[1]}{'.hidden' if hidden else ''}", pno, text))
        for wdg in page.widgets() or []:
            if wdg.field_value and str(wdg.field_value).strip() not in ("", "Off"):
                out.append(("form_field", pno, str(wdg.field_value)))
    for i in range(doc.embfile_count()):
        info = doc.embfile_info(i)
        out.append(("embedded_file.name", None, f"{info.get('filename', '')} {info.get('description', '')}"))
        try:
            data = doc.embfile_get(i)
            if len(data) < 2_000_000:
                out.append(("embedded_file.content", None, data.decode("utf-8", "ignore")))
        except Exception:
            pass
    return out


def structural_findings(doc, raw: bytes) -> list[Finding]:
    f: list[Finding] = []
    seen = set()
    for x in range(1, doc.xref_length()):
        try:
            obj = doc.xref_object(x, compressed=False).encode("latin-1", "ignore")
        except Exception:
            continue
        for rx, check, sev, msg in _ACTIVE:
            if check not in seen and rx.search(obj):
                seen.add(check)
                f.append(Finding(check=check, severity=sev, message=msg))
    cat = doc.pdf_catalog()
    oa = doc.xref_get_key(cat, "OpenAction")
    if oa[0] != "null" and "javascript" in seen:
        f.append(Finding(check="open_action", severity="high", message="JavaScript runs when the document opens"))

    try:
        ocgs = doc.get_ocgs() or {}
    except Exception:
        ocgs = {}
    off = [v.get("name", "?") for v in ocgs.values() if not v.get("on", True)]
    if off:
        f.append(Finding(check="hidden_layer", severity="high", reason="ocg_off", text=clip(", ".join(off)),
                         message=f"{len(off)} optional-content layer(s) are off by default; their text is "
                                 "invisible in viewers but extracted by some parsers"))

    n = doc.embfile_count()
    if n:
        f.append(Finding(check="embedded_file", severity="medium",
                         message=f"{n} embedded file(s); loaders that unpack attachments will ingest them"))

    eofs = raw.count(b"%%EOF")
    if eofs > 1:
        f.append(Finding(check="incremental_update", severity="low", reason=f"{eofs}_revisions",
                         message=f"file has {eofs} revisions (incremental updates); earlier revisions can hide "
                                 "or shadow content"))
    return f
