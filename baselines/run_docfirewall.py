"""Run DocFirewall over the same attacked + clean corpora readerguard is evaluated on.

    baselines/.venv-df/bin/python baselines/run_docfirewall.py balanced|strict
    -> bench/out/baseline_docfirewall_<profile>.jsonl  rows: {file, kind, verdict, findings, error, seconds}

Verdict mapping used in the paper: BLOCK ~ safe:false, FLAG ~ warn, ALLOW ~ pass.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import warnings
from multiprocessing import get_context
from pathlib import Path

OUT = Path("bench/out")
PROFILE = sys.argv[1] if len(sys.argv) > 1 else "balanced"
_SCANNER = None


def files():
    rows = []
    for r in json.loads((OUT / "results.json").read_text())["attacks"]:
        rows.append({"file": r["file"], "kind": "attack"})
    for r in json.loads((OUT / "multi_results.json").read_text())["attacks"]:
        rows.append({"file": r["file"], "kind": "attack"})
    for k, rs in json.loads((OUT / "results.json").read_text())["clean"].items():
        if "as released" not in k:
            rows += [{"file": r["file"], "kind": "clean"} for r in rs]
    for r in json.loads((OUT / "multi_results.json").read_text())["clean"]:
        rows.append({"file": r["file"], "kind": "clean"})
    return rows


def _init():
    global _SCANNER
    logging.disable(logging.WARNING)
    warnings.filterwarnings("ignore")
    os.environ.setdefault("DOC_FIREWALL_LOG_LEVEL", "ERROR")
    try:  # torch's MPS backend crashes on this machine (NSInvalidArgumentException); run ML detectors on CPU.
        import torch
        from transformers import pipeline  # noqa: F401  (import before patching mps, or transformers' import breaks)
        torch.backends.mps.is_available = lambda: False
        torch.set_num_threads(2)
    except ImportError:
        pass
    from doc_firewall import ScanConfig, Scanner
    cfg = ScanConfig(profile=PROFILE)
    cfg = cfg.apply_profile() if hasattr(cfg, "apply_profile") else cfg
    _SCANNER = Scanner(config=cfg)


def one(row):
    t = time.time()
    try:
        r = _SCANNER.scan(row["file"])
        return {**row, "verdict": r.verdict.value, "error": None, "seconds": round(time.time() - t, 3),
                "findings": [f"{getattr(f, 'severity', '')}: {getattr(f, 'title', '')}"[:120] for f in r.findings][:12]}
    except Exception as e:
        return {**row, "verdict": None, "error": f"{type(e).__name__}: {str(e)[:120]}", "seconds": round(time.time() - t, 3),
                "findings": []}


def sample(rows, per_group=2, clean_per_format=20):
    """Stratified, deterministic: first `per_group` attacked files per (format, technique, payload), first
    `clean_per_format` clean files per format (strict profile is ~35 s/file on CPU)."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from bench.compare import corpus
    meta = corpus()
    seen, out = {}, []
    for r in rows:
        v = meta.get(r["file"])
        if v is None:
            continue
        key = (v["format"], v.get("technique"), v.get("payload")) if r["kind"] == "attack" else (v["format"], "clean")
        cap = per_group if r["kind"] == "attack" else clean_per_format
        if seen.get(key, 0) < cap:
            seen[key] = seen.get(key, 0) + 1
            out.append(r)
    return out


if __name__ == "__main__":
    rows = files()
    if "--sample" in sys.argv:
        rows = sample(rows)
    dst = OUT / f"baseline_docfirewall_{PROFILE}.jsonl"
    done = set()
    if dst.exists():
        done = {json.loads(l)["file"] for l in dst.open()}
    rows = [r for r in rows if r["file"] not in done]
    print(len(rows), "to scan", flush=True)
    with get_context("spawn").Pool(int(os.environ.get("DF_PROCS", "6")), initializer=_init) as pool, dst.open("a") as f:
        for i, res in enumerate(pool.imap(one, rows, chunksize=4)):
            f.write(json.dumps(res) + "\n")
            f.flush()
            if i % 50 == 0:
                print(i, len(rows), flush=True)
    print("->", dst)
