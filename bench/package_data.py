"""Package the generated test data (attacked + clean files, results) as one zip for release.

    .venv/bin/python -m bench.package_data [--pdfbench ../pdfbench/data] [--out dist]
    -> dist/readerguard-testdata-v1.zip  and  dist/readerguard-testdata-v1.zip.sha256

Everything in the zip is synthetic or generated here, except that the 10 real public PDFs used as clean
controls are NOT included (third-party copyright); real_pdf_sources.json lists their URLs and SHA-256 so they
can be downloaded and checked. Paths inside the zip mirror the repository (bench/out/...) and pdfbench
(pdfbench/data/...); manifest.csv maps every file to its format, kind, technique, payload and canary.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path

NAME = "readerguard-testdata-v1"
OUT = Path("bench/out")
RESULTS = ["results.json", "multi_results.json", "exposure.json", "compare.json", "e2e_inputs.jsonl",
           "e2e_qwen3-235b.jsonl", "e2e_llama3.3-70b.jsonl", "e2e_qwen3-vl-235b.jsonl", "e2e_summary.json",
           "baseline_docfirewall_balanced.jsonl", "baseline_docfirewall_strict.jsonl", "baseline_phantomlint.jsonl"]
DOMAINS = ["insurance", "automotive", "pharma", "education", "computers"]

DATA_README = """# readerguard test data (v1)

Test files for checking whether document scanners catch content that a parser extracts but a person cannot
see. Built by the scripts in the readerguard repository's `bench/` folder from pdfbench, a synthetic document
set in which every company, person and product is fictional.

## Contents

| folder | what |
|---|---|
| `bench/out/attacks/<technique>/<instruction or fact>/` | attacked PDFs |
| `bench/out/multi/<format>/<technique>/<instruction or fact or active>/` | attacked HTML, Word, PowerPoint, Excel, Markdown, image and SVG files |
| `bench/out/clean/<format>/` | clean HTML, Word, PowerPoint, Excel, Markdown, image and SVG files |
| `pdfbench/data/<domain>/_text_layer/` | clean born-digital PDFs (also the sources of the attacked PDFs) |
| `pdfbench/data/mp_c5_on/pdfs/` | clean scanned PDFs (no text layer) |
| `results/` | per-file results: readerguard, loader exposure, LLM answers, DocFirewall, PhantomLint |
| `manifest.csv` | one row per file: path, format, kind (attack/clean), technique, payload, canary |
| `real_pdf_sources.json` | URLs and SHA-256 of the 10 real public PDFs used as clean controls (not included) |

## Payloads

Every attacked file carries one harmless sentence with a unique canary token (`ZQ` + 5 digits + `X`):

- `instruction`: tells the model to say the policy offers "full coverage" (contains trigger words)
- `fact`: states a false "400 days" waiting period (no trigger words)
- `active`: defanged active content (macros, DDE, JavaScript, SVG scripts) that runs `echo` or `alert(1)`
  and points at `example.net`

`visible_injection` files put the instruction payload in plain sight; they are a control, not a hidden attack.
The 10 SVG files under `svg_script/` and `svg_onload/` sit in `instruction/` folders but carry a defanged script
instead of a canary sentence (their `canary` in `manifest.csv` is empty).

Some files contain defanged macro, DDE or script samples. Antivirus software may still flag them. Open them only
in a test environment, and use them only on systems you are authorised to test.

## Counts

{counts}

License: not yet decided. The code that generated the data is in the readerguard repository (Apache-2.0).
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdfbench", default="../pdfbench/data")
    ap.add_argument("--out", default="dist")
    a = ap.parse_args()
    pdfbench = Path(a.pdfbench)
    dst = Path(a.out) / f"{NAME}.zip"
    dst.parent.mkdir(parents=True, exist_ok=True)

    p = json.loads((OUT / "results.json").read_text())
    mu = json.loads((OUT / "multi_results.json").read_text())
    rows = []
    for r in p["attacks"]:
        rows.append(dict(path=r["file"], format="pdf", kind="attack", technique=r["technique"],
                         payload=r["payload"], canary=r.get("canary", "")))
    for r in mu["attacks"]:
        rows.append(dict(path=r["file"], format=r["format"], kind="attack", technique=r["technique"],
                         payload=r["payload"], canary=r.get("canary", "")))
    for r in mu["clean"]:
        rows.append(dict(path=r["file"], format=r["format"], kind="clean", technique="", payload="", canary=""))
    pdf_sets = {"pdfbench born-digital (attack sources)", "pdfbench scanned variants (mp_c5_on)"}
    for k, rs in p["clean"].items():
        if k in pdf_sets:
            for r in rs:
                rows.append(dict(path=r["file"].split("../", 1)[-1],
                                 src=r["file"], format="pdf", kind="clean", technique="", payload="", canary=""))

    counts = {}
    for r in rows:
        counts[(r["format"], r["kind"])] = counts.get((r["format"], r["kind"]), 0) + 1
    fmts = sorted({f for f, _ in counts})
    table = "| format | attacked | clean |\n|---|---|---|\n" + "\n".join(
        f"| {f} | {counts.get((f, 'attack'), 0)} | {counts.get((f, 'clean'), 0)} |" for f in fmts)
    table += f"\n| **all** | **{sum(v for (f, k), v in counts.items() if k == 'attack')}** | " \
             f"**{sum(v for (f, k), v in counts.items() if k == 'clean')}** |"
    vis = sum(1 for r in rows if r["technique"] == "visible_injection")
    table += (f"\n\nAttacked counts include {vis} `visible_injection` controls, so there are "
              f"{sum(v for (f, k), v in counts.items() if k == 'attack') - vis} hidden-content attacks. "
              "Clean PDFs exclude the 10 real public PDFs (see `real_pdf_sources.json`).")

    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for r in rows:
            src = Path(r.pop("src", r["path"]))
            z.write(src, f"{NAME}/{r['path']}")
        for f in RESULTS:
            if (OUT / f).exists():
                z.write(OUT / f, f"{NAME}/results/{f}")
        z.write(pdfbench / "real" / "sources.json", f"{NAME}/real_pdf_sources.json")
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=["path", "format", "kind", "technique", "payload", "canary"])
        w.writeheader()
        w.writerows(rows)
        z.writestr(f"{NAME}/manifest.csv", buf.getvalue())
        z.writestr(f"{NAME}/README.md", DATA_README.replace("{counts}", table))

    h = hashlib.sha256(dst.read_bytes()).hexdigest()
    (dst.parent / (dst.name + ".sha256")).write_text(f"{h}  {dst.name}\n")
    print(f"{dst}  {dst.stat().st_size / 1e6:.1f} MB  {len(rows)} files  sha256 {h}")
    print(table)


if __name__ == "__main__":
    main()
