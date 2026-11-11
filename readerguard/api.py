"""scan(): one call for any document or URL.

    >>> from readerguard import scan
    >>> r = scan("https://example.com/page")          # or a path, bytes, or a file object
    >>> r.safe, r.message
    (False, 'not safe: hidden text on the page (zero_font): "Ignore previous instructions…"; ...')
    >>> r.to_dict()                                    # JSON-ready: safe, message, verdict, reasons, findings
    >>> r.safe_text                                    # visible text only, for indexing
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .fetch import FetchError, FetchOptions, fetch, resource_fetcher
from .findings import Finding, Report, sev_rank

TEXT_EXT = {".md": "markdown", ".markdown": "markdown", ".mdx": "markdown", ".txt": "text", ".csv": "text",
            ".tsv": "text", ".json": "text", ".log": "text", ".rst": "text", ".yaml": "text", ".yml": "text",
            ".xml": "text"}
CTYPE = {"text/html": "html", "application/xhtml+xml": "html", "application/pdf": "pdf", "image/svg+xml": "svg",
         "text/markdown": "markdown", "text/plain": "text", "application/rtf": "rtf", "text/rtf": "rtf"}


def sniff(raw: bytes, name: str = "", content_type: str = "") -> str:
    head = raw[:4096]
    if b"%PDF-" in raw[:1024]:
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
            names = set(z.namelist()[:5000])
        except zipfile.BadZipFile:
            return "zip"
        if "word/document.xml" in names:
            return "docx"
        if "ppt/presentation.xml" in names:
            return "pptx"
        if "xl/workbook.xml" in names:
            return "xlsx"
        if "mimetype" in names and z.read("mimetype")[:60].startswith(b"application/vnd.oasis.opendocument"):
            return "odf"
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM", b"II*\x00", b"MM\x00*")) or (
            head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "image"
    if head.startswith(b"MZ") or head.startswith(b"\x7fELF") or head[:4] in (
            b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "executable"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if b"\x00" in head.replace(b"\x00\x00", b"") and not head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "binary"
    low = head.lower().lstrip(b"\xef\xbb\xbf \t\r\n")
    if low.startswith(b"#!"):
        return "script"
    if b"<svg" in low[:1024] and (low.startswith(b"<svg") or low.startswith(b"<?xml") or low.startswith(b"<!doctype svg")):
        return "svg"
    if low.startswith((b"<!doctype html", b"<html")) or re.search(rb"<(html|head|body)[\s>]", low[:2048]):
        return "html"
    ct = CTYPE.get(content_type)
    if ct:
        return ct
    ext = Path(name).suffix.lower()
    if ext in (".html", ".htm", ".xhtml"):
        return "html"
    return TEXT_EXT.get(ext, "markdown" if ext == "" else "text")


@dataclass
class ScanResult:
    safe: bool
    message: str
    verdict: str                  # pass / warn / fail
    format: str
    source: str
    reasons: list[str]
    findings: list[Finding] = field(default_factory=list)
    safe_text: str = ""
    error: str | None = None

    def __bool__(self):
        return self.safe

    def to_dict(self, include_text: bool = False) -> dict:
        d = {"safe": self.safe, "message": self.message, "verdict": self.verdict, "format": self.format,
             "source": self.source, "reasons": self.reasons,
             "findings": [f.to_dict() for f in self.findings if f.severity != "info"]}
        if self.error:
            d["error"] = self.error
        if include_text:
            d["safe_text"] = self.safe_text
        return d


def _reason(f: Finding) -> str:
    where = f" (page {f.page + 1})" if f.page is not None else ""
    s = f.message + where
    if f.text and f.check in ("prompt_injection", "hidden_text", "unicode_smuggling", "malicious_script",
                              "remote_content", "dde", "dangerous_formula", "exfiltration_image"):
        s += f': "{f.text[:80]}"'
    return s


def _result(rep: Report, source: str, strict: bool) -> ScanResult:
    v = rep.verdict
    safe = v == "pass" if strict else v != "fail"
    ranked = sorted((f for f in rep.findings if f.severity not in ("info",)), key=lambda f: -sev_rank(f.severity))
    seen, reasons = set(), []
    for f in ranked:
        key = (f.check, f.reason)
        if key in seen:
            continue
        seen.add(key)
        reasons.append(f"[{f.severity}] {_reason(f)}")
    top = [r.split("] ", 1)[1] for r in reasons if not r.startswith(("[low]", "[info]"))][:3]
    if rep.error and not top:
        top = [rep.error]
    if not safe:
        msg = "not safe: " + "; ".join(top) + (f" (+{len(reasons) - len(top)} more)" if len(reasons) > len(top) else "")
    elif v == "warn":
        msg = "success (with warnings): " + "; ".join(top)
    else:
        msg = "success"
    return ScanResult(safe=safe, message=msg, verdict=v, format=rep.format, source=source, reasons=reasons,
                      findings=rep.findings, safe_text=rep.safe_text, error=rep.error)


def scan_report(source, *, name: str | None = None, fetch_options: FetchOptions | None = None,
                ocr: bool | str = "auto", ocr_fn=None, differential: bool = True) -> Report:
    """Same as scan() but returns the full Report (findings, safe_pages, raw_pages)."""
    pre: list[Finding] = []
    base_url, ctype, fetcher = None, "", None
    if isinstance(source, str) and re.match(r"^https?://", source, re.I):
        opt = fetch_options or FetchOptions()
        try:
            got = fetch(source, opt)
        except FetchError as e:
            rep = Report(path=source, format="url")
            rep.error = f"could not fetch URL, so its content was not verified ({e})"
            return rep
        raw, name, ctype, base_url = got.body, name or got.final_url, got.content_type, got.final_url
        pre += got.findings
        cd = got.headers.get("Content-Disposition") or got.headers.get("content-disposition") or ""
        m = re.search(r'filename\*?=["\']?(?:UTF-8\'\')?([^"\';]+)', cd)
        if m:
            name = m.group(1)
        if opt.fetch_resources:
            fetcher = resource_fetcher(opt)
    elif isinstance(source, (bytes, bytearray)):
        raw, name = bytes(source), name or "<bytes>"
    elif hasattr(source, "read"):
        raw, name = source.read(), name or getattr(source, "name", "<stream>")
    else:
        p = Path(source)
        raw, name = p.read_bytes(), name or str(p)

    kind = sniff(raw, name, ctype)
    rep = _dispatch(kind, raw, name, base_url, fetcher, ocr, ocr_fn, differential)
    rep.findings = pre + rep.findings

    ext = Path(urlparse(name).path).suffix.lower()
    expected = {".pdf": "pdf", ".docx": "docx", ".docm": "docx", ".pptx": "pptx", ".pptm": "pptx", ".xlsx": "xlsx",
                ".xlsm": "xlsx", ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
                ".webp": "image", ".svg": "svg", ".doc": "ole", ".xls": "ole", ".ppt": "ole", ".rtf": "rtf"}.get(ext)
    if expected and expected != kind and not (expected == "ole" and kind == "rtf"):
        rep.findings.append(Finding(check="type_mismatch", severity="high" if kind in ("executable", "html", "svg",
                                                                                     "script") else "medium",
                                    message=f"file is named {ext} but its content is {kind}"))
    return rep


def _dispatch(kind, raw, name, base_url, fetcher, ocr, ocr_fn, differential) -> Report:
    if kind == "pdf":
        from .pdf.validator import scan_pdf
        return scan_pdf(raw, name, differential_check=differential, ocr_check=ocr, ocr_fn=ocr_fn)
    if kind in ("html", "svg"):
        from .formats.html import scan_html
        return scan_html(raw, name, base_url=base_url, fetch_resource=fetcher, svg=kind == "svg")
    if kind in ("docx", "pptx", "xlsx", "odf"):
        from .formats.office import scan_ooxml
        return scan_ooxml(raw, name, kind)
    if kind == "ole":
        from .formats.office import scan_ole
        return scan_ole(raw, name)
    if kind == "rtf":
        from .formats.office import scan_rtf
        return scan_rtf(raw, name)
    if kind == "image":
        from .formats.image import scan_image
        return scan_image(raw, name, ocr_check=ocr, ocr_fn=ocr_fn)
    if kind in ("markdown", "text"):
        from .formats.text import scan_text
        return scan_text(raw, name, markdown=kind == "markdown")
    rep = Report(path=name, format=kind)
    if kind in ("executable", "script"):
        rep.findings.append(Finding(check="executable", severity="critical",
                                    message=f"content is an {'executable program' if kind == 'executable' else 'executable script'}, not a document"))
    else:
        rep.findings.append(Finding(check="unsupported_format", severity="high",
                                    message=f"unsupported or unknown format ({kind}); contents could not be verified"))
    return rep


def scan(source, *, strict: bool = False, name: str | None = None, fetch_options: FetchOptions | None = None,
         ocr: bool | str = "auto", ocr_fn=None, differential: bool = True) -> ScanResult:
    """Scan a path, URL, bytes or file object.

    safe is False when anything high/critical was found (verdict "fail"); with strict=True, medium
    findings (verdict "warn") also make it unsafe.
    """
    src = source if isinstance(source, str) else name or getattr(source, "name", "<bytes>") if not isinstance(
        source, Path) else str(source)
    rep = scan_report(source, name=name, fetch_options=fetch_options, ocr=ocr, ocr_fn=ocr_fn,
                      differential=differential)
    return _result(rep, str(src), strict)
