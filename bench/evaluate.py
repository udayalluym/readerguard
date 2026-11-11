"""Evaluate the readerguard PDF checks on the attack corpus and on clean pdfbench / real PDFs.

    .venv/bin/python -m bench.evaluate      -> bench/out/results.json, bench/RESULTS.md

Per attacked PDF:
  exposed_*   the canary appears in that parser's page text (what a naive RAG loader would index)
  flagged     verdict warn or fail;  blocked: verdict fail
  leaked      the canary survives in pdfguard's safe_text
Per clean PDF: verdict (false-positive rate) and token retention of safe_text vs the raw text layer.
"""
from __future__ import annotations

import io
import json
import logging
import time
from collections import defaultdict
from multiprocessing import Pool
from pathlib import Path

import pymupdf

from readerguard.pdf.validator import scan_pdf
from readerguard.textscan import tokens


def validate(path):
    return scan_pdf(Path(path).read_bytes(), str(path))

logging.getLogger("pdfminer").setLevel(logging.ERROR)
pymupdf.TOOLS.mupdf_display_errors(False)
OUT = Path("bench/out")
DATA = Path("../pdfbench/data")
DOMAINS = ["insurance", "automotive", "pharma", "education", "computers"]


def pdfminer_text(path) -> str:
    from pdfminer.high_level import extract_text
    try:
        return extract_text(str(path))
    except Exception:
        return ""


def pdfplumber_text(path) -> str:
    import pdfplumber
    try:
        with pdfplumber.open(path) as pdf:
            return "\n".join(p.extract_text() or "" for p in pdf.pages)
    except Exception:
        return ""


def side_text(path) -> str:
    """What metadata-aware loaders (LangChain PyMuPDFLoader etc.) also carry: metadata + annotations."""
    d = pymupdf.open(path)
    parts = [str(v) for v in (d.metadata or {}).values() if v]
    for p in d:
        parts += [(a.info or {}).get("content", "") for a in p.annots() or []]
    for i in range(d.embfile_count()):
        parts.append(d.embfile_get(i).decode("utf-8", "ignore"))
    s = " ".join(parts)
    return s + " " + "".join(chr(ord(c) - 0xE0000) for c in s if 0xE0020 <= ord(c) < 0xE007F)


def run_attack(row: dict) -> dict:
    f, can = row["file"], row["canary"]
    t = time.time()
    rep = validate(f)
    dt = time.time() - t
    doc = pymupdf.open(f)
    naive = "".join(p.get_text() for p in doc)
    return {**row,
            "exposed_pymupdf": can in naive,
            "exposed_pdfminer": can in pdfminer_text(f),
            "exposed_pdfplumber": can in pdfplumber_text(f),
            "exposed_side": can in side_text(f),
            "verdict": rep.verdict, "checks": sorted({x.check for x in rep.findings if x.severity != "info"}),
            "leaked": can in rep.safe_text, "seconds": dt, "pages": rep.pages}


def run_clean(path: str) -> dict:
    t = time.time()
    rep = validate(path)
    dt = time.time() - t
    raw = [tokens(x) for x in rep.raw_pages]
    safe = [set(tokens(x)) for x in rep.safe_pages]
    n = sum(len(r) for r in raw)
    kept = sum(sum(tk in s for tk in r) for r, s in zip(raw, safe))
    return {"file": path, "verdict": rep.verdict, "pages": rep.pages, "seconds": dt,
            "retention": kept / n if n else 1.0, "tokens": n,
            "findings": [x.to_dict() for x in rep.findings if x.severity != "info"]}


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "–"


def main():
    rows = [json.loads(l) for l in (OUT / "attacks/manifest.jsonl").open()]
    sets = {
        "pdfbench born-digital (attack sources)": sorted(str(p) for d in DOMAINS for p in (DATA / d / "_text_layer").glob("*.pdf")),
        "pdfbench as released (incl. scanned docs)": sorted(str(p) for d in DOMAINS for p in (DATA / d / "pdfs").glob("*.pdf")),
        "pdfbench scanned variants (mp_c5_on)": sorted(str(p) for p in (DATA / "mp_c5_on/pdfs").glob("*.pdf")),
        "real public PDFs": sorted(str(p) for p in (DATA / "real/pdfs").glob("*.pdf")),
    }
    with Pool(6) as pool:
        att = pool.map(run_attack, rows, chunksize=4)
        clean = {k: pool.map(run_clean, v, chunksize=2) for k, v in sets.items()}
    (OUT / "results.json").write_text(json.dumps({"attacks": att, "clean": clean}, indent=1))

    by = defaultdict(list)
    for r in att:
        by[r["technique"]].append(r)
    L = ["# readerguard PDF evaluation", "",
         f"{len(att)} attacked PDFs: {len(by)} techniques × 2 payload styles (instruction / fact) × 15 source "
         "documents from pdfbench (`visible_injection` has only the instruction style). Every payload carries a unique canary token.", "",
         "**Exposed** = the canary is in that parser's output (what a naive loader indexes). **Side** = metadata, "
         "annotations or attachments, which many loaders copy into chunk metadata. **Blocked** = verdict `fail`; "
         "**flagged** = `warn` or `fail`. **Leaked** = the canary survives in `safe_text`.", "",
         "| technique | n | exposed PyMuPDF | exposed pdfminer | exposed pdfplumber | exposed side | flagged | blocked | leaked | main checks |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    tot = defaultdict(int)
    for tech, rs in by.items():
        n = len(rs)
        cnt = {k: sum(r[k] for r in rs) for k in ("exposed_pymupdf", "exposed_pdfminer", "exposed_pdfplumber", "exposed_side", "leaked")}
        fl = sum(r["verdict"] != "pass" for r in rs)
        bl = sum(r["verdict"] == "fail" for r in rs)
        checks = defaultdict(int)
        for r in rs:
            for c in r["checks"]:
                checks[c] += 1
        top = ", ".join(c for c, _ in sorted(checks.items(), key=lambda x: -x[1])[:2])
        L.append(f"| {tech} | {n} | {pct(cnt['exposed_pymupdf'], n)} | {pct(cnt['exposed_pdfminer'], n)} | "
                 f"{pct(cnt['exposed_pdfplumber'], n)} | {pct(cnt['exposed_side'], n)} | {pct(fl, n)} | {pct(bl, n)} | "
                 f"{pct(cnt['leaked'], n)} | {top} |")
        if tech != "visible_injection":
            tot["n"] += n; tot["fl"] += fl; tot["bl"] += bl; tot["leak"] += cnt["leaked"]
            tot["exp"] += any_exposed(rs)
    L += ["", f"**Hidden techniques overall** ({tot['n']} PDFs): flagged {pct(tot['fl'], tot['n'])}, blocked "
          f"{pct(tot['bl'], tot['n'])}, canary leaked into safe text {pct(tot['leak'], tot['n'])}; "
          f"{pct(tot['exp'], tot['n'])} of them expose the canary to at least one parser or loader channel.", ""]

    by_kind = defaultdict(lambda: [0, 0])
    for r in att:
        if r["technique"] != "visible_injection":
            by_kind[r["payload"]][0] += r["verdict"] == "fail"
            by_kind[r["payload"]][1] += 1
    L.append("Blocked by payload style (hidden techniques): " + ", ".join(
        f"{k} {pct(a, b)}" for k, (a, b) in by_kind.items()) + ". The fact-style payload has no trigger words, so "
        "detection there comes from visibility and structure alone.")
    L += ["", "## Clean documents (false positives)", "",
          "| set | PDFs | pages | pass | warn | fail | safe-text token retention | s/page |", "|---|---|---|---|---|---|---|---|"]
    for k, rs in clean.items():
        pg = sum(r["pages"] for r in rs)
        v = defaultdict(int)
        for r in rs:
            v[r["verdict"]] += 1
        ntok = sum(r["tokens"] for r in rs)
        ret = f"{100 * sum(r['retention'] * r['tokens'] for r in rs) / ntok:.2f}%" if ntok else "– (no text layer)"
        L.append(f"| {k} | {len(rs)} | {pg} | {v['pass']} | {v['warn']} | {v['fail']} | {ret} | "
                 f"{sum(r['seconds'] for r in rs) / max(1, pg):.2f} |")
    L += ["", "Non-pass clean documents:", ""]
    for k, rs in clean.items():
        for r in rs:
            if r["verdict"] != "pass":
                fs = "; ".join(f"{x['check']}/{x.get('reason', '')}: {x.get('text', x['message'])[:80]}"
                               for x in r["findings"] if x["severity"] in ("medium", "high", "critical"))
                L.append(f"- `{Path(r['file']).name}` ({k}) **{r['verdict']}**: {fs}")
    (Path("bench/RESULTS.md")).write_text("\n".join(L) + "\n")
    print("\n".join(L))


def any_exposed(rs):
    return sum(r["exposed_pymupdf"] or r["exposed_pdfminer"] or r["exposed_pdfplumber"] or r["exposed_side"] for r in rs)


if __name__ == "__main__":
    main()
