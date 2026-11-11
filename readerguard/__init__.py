"""readerguard: check documents and web pages before they reach a RAG index or an LLM.

    from readerguard import scan
    r = scan("upload.docx")            # path, URL, bytes or file object
    r.safe, r.message                  # True/False, "success" / "not safe: <reasons>"
    r.safe_text                        # visible text only
    r.to_dict()                        # JSON-ready

Formats: PDF, HTML / URLs, SVG, DOCX / PPTX / XLSX (+ macro-enabled), OpenDocument, RTF, legacy
.doc/.xls/.ppt (macro check only), Markdown, plain text, PNG / JPEG / GIF / WebP / BMP / TIFF.
"""
from .api import ScanResult, scan, scan_report, sniff
from .fetch import FetchOptions
from .findings import SEVERITIES, Finding, Report

__all__ = ["scan", "scan_report", "sniff", "ScanResult", "FetchOptions", "Report", "Finding", "SEVERITIES"]
__version__ = "0.2.0"
