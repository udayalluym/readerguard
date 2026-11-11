#!/usr/bin/env bash
# Build the clean HTML / Word / Markdown / PowerPoint corpus from pdfbench's HTML sources.
#   bash bench/build_clean.sh [PDFBENCH_DATA] [OUT]      (defaults: ../pdfbench/data  bench/out/clean)
# Needs pandoc. Excel, image and SVG clean files are made afterwards by `python -m bench.multi build`.
set -euo pipefail
SRC=${1:-../pdfbench/data}
OUT=${2:-bench/out/clean}
mkdir -p "$OUT"/{html,docx,md,pptx}
for d in insurance automotive pharma education computers; do
  cp "$SRC/$d/_html/"*.html "$OUT/html/"
done
for f in "$OUT"/html/*.html; do
  b=$(basename "$f" .html)
  pandoc "$f" -o "$OUT/docx/$b.docx" 2>/dev/null
  pandoc "$f" -t gfm -o "$OUT/md/$b.md" 2>/dev/null
done
# every third document also becomes a slide deck
for f in $(ls "$OUT"/html/*.html | awk 'NR%3==0'); do
  pandoc "$f" -o "$OUT/pptx/$(basename "$f" .html).pptx" 2>/dev/null
done
echo "html $(ls "$OUT/html" | wc -l)  docx $(ls "$OUT/docx" | wc -l)  md $(ls "$OUT/md" | wc -l)  pptx $(ls "$OUT/pptx" | wc -l)"
