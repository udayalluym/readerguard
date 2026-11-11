"""Run PhantomLint (Murray, arXiv 2508.17884; github.com/tobycmurray/phantom-lint) over the attacked + clean PDF/HTML files.

Uses the CLI defaults (noop splitter, nlp analyzer @0.75, word_exact differ, 300 dpi, default bad-phrase list).
OCR: Tesseract when available (the original), else Apple Vision via ocrmac behind PhantomLint's own OCREngine
interface, keeping its low-contrast suppression step. Other formats are recorded as unsupported.

    baselines/.venv-pl/bin/python baselines/run_phantomlint.py [tesseract|vision]
    -> bench/out/baseline_phantomlint.jsonl   rows: {file, kind, supported, hidden, suspicious, error, seconds, ocr}
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
import time
from multiprocessing import get_context
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from run_docfirewall import files  # same corpus list

OUT = Path("bench/out")
ENGINE = sys.argv[1] if len(sys.argv) > 1 else ("tesseract" if shutil.which("tesseract") else "vision")
_P = {}


def _init():
    logging.disable(logging.WARNING)
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    from phantomlint.analyzers import LocalSemanticAnalyzer
    from phantomlint.cli import DEFAULT_BADLIST, DEFAULT_DPI, DEFAULT_THRESHOLD
    from phantomlint.diffing import WordDiffer
    from phantomlint.ocr import TesseractOCREngine, suppress_low_contrast_color
    from phantomlint.splitters import NoopSplitter

    if ENGINE == "tesseract":
        ocr = TesseractOCREngine()
    else:
        from ocrmac import ocrmac

        class VisionOCREngine:
            def extract_text(self, images):
                out = []
                for img in images:
                    img = suppress_low_contrast_color(img)
                    out.append("\n".join(t for t, _, _ in ocrmac.OCR(img, recognition_level="accurate").recognize()))
                return "\n".join(out)
        ocr = VisionOCREngine()
    _P.update(ocr=ocr, splitter=NoopSplitter(), differ=WordDiffer(threshold=1.0),
              analyzer=LocalSemanticAnalyzer(threshold=DEFAULT_THRESHOLD), bad=DEFAULT_BADLIST, dpi=DEFAULT_DPI)


def one(row):
    from phantomlint.detector import HIDDEN_SUSPICIOUS_PHRASES_FILE, SUSPICIOUS_PHRASES_FILE, detect_hidden_phrases
    from phantomlint.renderer import renderer_for
    t = time.time()
    p = Path(row["file"])
    base = {**row, "ocr": ENGINE}
    renderer = renderer_for(p, _P["dpi"])
    if renderer is None:
        return {**base, "supported": False, "hidden": False, "suspicious": False, "error": None, "seconds": 0}
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        try:
            detect_hidden_phrases(p, d, _P["ocr"], _P["splitter"], _P["differ"], _P["analyzer"], renderer, _P["bad"])
            err = None
        except SystemExit:
            err = None
        except Exception as e:
            err = f"{type(e).__name__}: {str(e)[:120]}"
        hid = (d / HIDDEN_SUSPICIOUS_PHRASES_FILE).exists() and (d / HIDDEN_SUSPICIOUS_PHRASES_FILE).read_text().strip() != ""
        sus = (d / SUSPICIOUS_PHRASES_FILE).exists() and (d / SUSPICIOUS_PHRASES_FILE).read_text().strip() != ""
    return {**base, "supported": True, "hidden": hid, "suspicious": sus, "error": err, "seconds": round(time.time() - t, 2)}


if __name__ == "__main__":
    rows = files()
    dst = OUT / "baseline_phantomlint.jsonl"
    done = set()
    if dst.exists():
        done = {json.loads(l)["file"] for l in dst.open()}
    todo = [r for r in rows if r["file"] not in done]
    print(f"engine={ENGINE}: {len(todo)} to scan ({len(done)} done)", flush=True)
    with get_context("spawn").Pool(int(os.environ.get("PL_PROCS", "4")), initializer=_init) as pool, dst.open("a") as f:
        for i, res in enumerate(pool.imap_unordered(one, todo, chunksize=2)):
            f.write(json.dumps(res) + "\n")
            f.flush()
            if i % 100 == 0:
                print(i, len(todo), flush=True)
    print("->", dst)
