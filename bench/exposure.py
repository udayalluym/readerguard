"""Which popular loaders pass hidden payloads through to the text an LLM sees?

For every attacked file that carries a canary, run common loaders and record whether the canary is in
their output. -> bench/out/exposure.json, bench/EXPOSURE.md

    .venv/bin/python -m bench.exposure
"""
from __future__ import annotations

import json
import logging
import warnings
from collections import defaultdict
from multiprocessing import get_context
from pathlib import Path

OUT = Path("bench/out")
logging.disable(logging.WARNING)
warnings.filterwarnings("ignore")


def _markitdown(p):
    from markitdown import MarkItDown
    return MarkItDown().convert(str(p)).text_content


def _bs4(p):
    from bs4 import BeautifulSoup
    return BeautifulSoup(Path(p).read_bytes(), "html.parser").get_text(" ")


def _html2text(p):
    import html2text
    return html2text.html2text(Path(p).read_text(errors="ignore"))


def _python_docx(p):
    import docx
    d = docx.Document(p)
    parts = [x.text for x in d.paragraphs]
    for t in d.tables:
        parts += [c.text for r in t.rows for c in r.cells]
    return "\n".join(parts)


def _docx2txt(p):
    import docx2txt
    return docx2txt.process(p)


def _python_pptx(p):
    from pptx import Presentation
    prs = Presentation(p)
    out = []
    for s in prs.slides:
        for sh in s.shapes:
            if sh.has_text_frame:
                out.append(sh.text_frame.text)
        if s.has_notes_slide:
            out.append(s.notes_slide.notes_text_frame.text)
    return "\n".join(out)


def _openpyxl(p):
    import openpyxl
    wb = openpyxl.load_workbook(p, data_only=False)
    return "\n".join(str(c.value) for ws in wb.worksheets for row in ws.iter_rows() for c in row if c.value is not None)


def _raw(p):
    return Path(p).read_text(errors="ignore")


def _pymupdf(p):
    import pymupdf
    return "".join(pg.get_text() for pg in pymupdf.open(p))


def _pdfminer(p):
    from pdfminer.high_level import extract_text
    return extract_text(str(p))


def _readerguard(p):
    from readerguard import scan
    return scan(str(p)).safe_text


LOADERS = {
    "pdf": {"PyMuPDF": _pymupdf, "pdfminer.six": _pdfminer, "MarkItDown": _markitdown},
    "html": {"BeautifulSoup": _bs4, "html2text": _html2text, "MarkItDown": _markitdown},
    "docx": {"python-docx": _python_docx, "docx2txt": _docx2txt, "MarkItDown": _markitdown},
    "pptx": {"python-pptx": _python_pptx, "MarkItDown": _markitdown},
    "xlsx": {"openpyxl": _openpyxl, "MarkItDown": _markitdown},
    "markdown": {"raw text": _raw, "MarkItDown": _markitdown},
    "svg": {"BeautifulSoup": _bs4, "raw text": _raw},
    "image": {"MarkItDown": _markitdown},
}


def _decode_tags(s: str) -> str:
    """Unicode tag characters are invisible but tokenizers read them: decode to ASCII before matching."""
    return s + " " + "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0020 <= ord(c) < 0xE007F)


def run(row):
    out = {**row, "exposed": {}}
    for name, fn in list(LOADERS[row["format"]].items()) + [("readerguard safe_text", _readerguard)]:
        try:
            out["exposed"][name] = row["canary"] in _decode_tags(fn(row["file"]) or "")
        except Exception as e:
            out["exposed"][name] = None
            out.setdefault("errors", {})[name] = type(e).__name__
    return out


def main():
    rows = [json.loads(l) for l in (OUT / "multi/manifest.jsonl").open()]
    rows += [{**json.loads(l), "format": "pdf"} for l in (OUT / "attacks/manifest.jsonl").open()]
    rows = [r for r in rows if r.get("canary") and r["technique"] not in ("visible_injection", "javascript")]
    with get_context("spawn").Pool(6) as pool:
        res = pool.map(run, rows, chunksize=4)
    (OUT / "exposure.json").write_text(json.dumps(res, indent=1))

    L = ["# Loader exposure", "", "Share of attacked files whose hidden canary appears in each loader's output "
         "(visible-injection baseline excluded).", ""]
    by_fmt = defaultdict(list)
    for r in res:
        by_fmt[r["format"]].append(r)
    for fmt, rs in by_fmt.items():
        names = list(LOADERS[fmt]) + ["readerguard safe_text"]
        L += [f"## {fmt}", "", "| technique | n | " + " | ".join(names) + " |", "|---" * (len(names) + 2) + "|"]
        by_t = defaultdict(list)
        for r in rs:
            by_t[r["technique"]].append(r)
        for tech, ts in sorted(by_t.items()):
            cells = []
            for nm in names:
                vals = [t["exposed"].get(nm) for t in ts if t["exposed"].get(nm) is not None]
                cells.append(f"{100 * sum(vals) / len(vals):.0f}%" if vals else "err")
            L.append(f"| {tech} | {len(ts)} | " + " | ".join(cells) + " |")
        tot = []
        for nm in names:
            vals = [t["exposed"].get(nm) for t in rs if t["exposed"].get(nm) is not None]
            tot.append(f"**{100 * sum(vals) / len(vals):.0f}%**" if vals else "err")
        L += [f"| **all** | {len(rs)} | " + " | ".join(tot) + " |", ""]
    Path("bench/EXPOSURE.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
