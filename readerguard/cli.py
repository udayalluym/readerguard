"""readerguard scan <paths|dirs|URLs> [--json] [--strict]   exit code 0 safe, 1 safe with warnings, 2 not safe
   readerguard text <path|URL> [-o out.txt]                 visible-only text"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .api import scan
from .fetch import FetchOptions

SUFFIXES = {".pdf", ".html", ".htm", ".svg", ".docx", ".docm", ".pptx", ".pptm", ".xlsx", ".xlsm", ".odt", ".ods",
            ".odp", ".rtf", ".doc", ".xls", ".ppt", ".md", ".markdown", ".txt", ".png", ".jpg", ".jpeg", ".gif",
            ".webp", ".bmp", ".tif", ".tiff", ".csv", ".json"}


def _sources(items):
    for s in items:
        if s.startswith(("http://", "https://")):
            yield s
            continue
        p = Path(s)
        if p.is_dir():
            yield from (str(f) for f in sorted(p.rglob("*")) if f.is_file() and f.suffix.lower() in SUFFIXES)
        else:
            yield s


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="readerguard", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="check documents / URLs")
    s.add_argument("sources", nargs="+")
    s.add_argument("--json", action="store_true")
    s.add_argument("--strict", action="store_true", help="treat warnings as unsafe")
    s.add_argument("-v", "--verbose", action="store_true", help="list every finding")
    t = sub.add_parser("text", help="print visible text only")
    t.add_argument("source")
    t.add_argument("-o", "--out")
    for p in (s, t):
        p.add_argument("--no-ocr", action="store_true")
        p.add_argument("--no-resources", action="store_true", help="do not fetch CSS/scripts linked from web pages")
        p.add_argument("--allow-private", action="store_true", help="allow URLs that resolve to private addresses")
    a = ap.parse_args(argv)
    fo = FetchOptions(fetch_resources=not a.no_resources, allow_private=a.allow_private)
    ocr = False if a.no_ocr else "auto"

    if a.cmd == "text":
        r = scan(a.source, fetch_options=fo, ocr=ocr)
        (Path(a.out).write_text if a.out else sys.stdout.write)(r.safe_text)
        print(f"[readerguard] safe={r.safe}: {r.message}", file=sys.stderr)
        return 0 if r.safe else 2

    worst = 0
    for src in _sources(a.sources):
        try:
            r = scan(src, strict=a.strict, fetch_options=fo, ocr=ocr)
        except Exception as e:  # never let one bad input stop a batch
            print(json.dumps({"source": src, "safe": False, "message": f"not safe: scanner error {e!r}"}) if a.json
                  else f"ERROR {src}: {e!r}")
            worst = 2
            continue
        code = 0 if r.verdict == "pass" else (1 if r.safe else 2)
        worst = max(worst, code)
        if a.json:
            print(json.dumps(r.to_dict()))
            continue
        print(f"{'SAFE  ' if r.safe else 'UNSAFE'} [{r.format}] {src}\n       {r.message}")
        if a.verbose:
            for line in r.reasons:
                print(f"         - {line}")
    return worst


if __name__ == "__main__":
    sys.exit(main())
