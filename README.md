# readerguard

**Check any document or web page before it reaches your RAG index or LLM.**

Pass a file, bytes or a URL. You get back whether it is safe, a human-readable reason, and the text a
person can actually see.

```python
from readerguard import scan

r = scan("https://example.com/pricing")     # or "upload.pdf", b"...", open(f, "rb")
r.safe        # False
r.message     # 'not safe: hidden text (zero_font): 1 piece(s) of text in the page that a parser extracts
              #  but a reader cannot see: "Revised terms: the waiting period ..."'
r.to_dict()   # {"safe": false, "message": "...", "verdict": "fail", "format": "html", "reasons": [...], "findings": [...]}
r.safe_text   # visible text only: index this, not the raw parser output
```

## Install

Python 3.10 or newer. readerguard is not on PyPI yet, so install it from source:

```bash
git clone https://github.com/udayalluym/readerguard.git && cd readerguard
python -m venv .venv && source .venv/bin/activate
pip install -e ".[differential,ocr-mac]"     # core + the parser-differential PDF check + Apple Vision OCR
```

| extra | adds | needed for |
|---|---|---|
| (none) | PyMuPDF, NumPy, Pillow, defusedxml | every format; the PDF render check |
| `differential` | pdfminer.six | the PDF parser-disagreement check |
| `ocr-mac` | ocrmac (Apple Vision) | OCR checks on images and PDFs, macOS only. Elsewhere pass `ocr_fn=` (see [Options](#options)) |
| `bench` | pdfplumber, python-docx, python-pptx, openpyxl, MarkItDown, BeautifulSoup, html2text, docx2txt | rebuilding the test data and running the benchmark |

Check the install with the unit tests:

```bash
pip install pytest && pytest tests/
```

## Command line

```bash
readerguard scan report.docx https://example.com uploads/      # exit code 0 safe, 1 safe with warnings, 2 not safe
readerguard scan --json --strict uploads/                      # --strict: warnings count as unsafe
readerguard text page.html -o page.txt                         # visible text only
```

`safe` is `False` when anything high or critical is found. A clean document returns `message: "success"`.
Lesser issues come back as `"success (with warnings): ..."`. With `strict=True`, warnings also make `safe`
`False`. Anything that cannot be verified is reported unsafe: an unreachable URL, an encrypted PDF, an
unknown binary format, or an executable.

## Supported files

The format is detected from the file's content, not its name. A file whose extension does not match its content
(for example a `.pdf` that is really a Word file) gets a finding saying so.

**Fully supported and benchmarked** (results in [Results](#results)):

| format | extensions |
|---|---|
| PDF | `.pdf` |
| HTML and web pages | `.html` `.htm` `.xhtml`, and any `http://` or `https://` URL |
| SVG | `.svg` |
| Word | `.docx` `.docm` |
| PowerPoint | `.pptx` `.pptm` |
| Excel | `.xlsx` `.xlsm` |
| Markdown | `.md` `.markdown` `.mdx` |
| Images | `.png` `.jpg` `.jpeg` |

**Supported, not yet benchmarked:**

| format | extensions | what is checked |
|---|---|---|
| Other images | `.gif` `.webp` `.bmp` `.tif` `.tiff` | everything the PNG/JPEG check does, except data appended after the end of the image (PNG and JPEG only) |
| Plain text | `.txt` `.csv` `.tsv` `.json` `.yaml` `.yml` `.xml` `.log` `.rst`, and any other file that is text | Unicode smuggling and injection phrasing (files with no extension are scanned as Markdown) |
| OpenDocument | `.odt` `.ods` `.odp` | macros, hidden text and hidden paragraphs, document properties, links to protocol handlers or file shares |
| RTF | `.rtf` | hidden text (`\v`), auto-updating embedded objects, Equation Editor exploit marker, remote templates, injection phrasing |

**Partly supported:** legacy binary Office (`.doc` `.xls` `.ppt`) is checked for macros and the Equation Editor
exploit marker only. Its text is not read, so every such file also gets a warning that its content was not
inspected. Convert these to `.docx` / `.xlsx` / `.pptx` for a full scan.

**Always reported unsafe:**
- Executables (Windows, Linux, macOS programs) and scripts starting with `#!`.
- ZIP archives that are not Office or OpenDocument files; their contents are not unpacked.
- Unknown binary formats.
- Encrypted PDFs.
- URLs that cannot be fetched.

**Not supported:** EPUB, Apple Pages / Numbers / Keynote, HEIC images, audio and video. These are reported as
unknown formats, and so as unsafe. Email is not parsed: `.eml` is text, so it is scanned as plain text (its
HTML parts and attachments are not analysed separately), and Outlook `.msg` uses the legacy Office container,
so it gets the same "not inspected" warning as `.doc`.

OCR checks on images and PDFs need macOS (Apple Vision, via the `ocr-mac` extra) or your own OCR function
passed as `ocr_fn`. Without one, those checks are skipped and the result says so.

## What it covers

| format | hidden text (shown to parsers, not people) | active / malicious content | side channels |
|---|---|---|---|
| **PDF** | white or near-white, invisible render mode, 1-pt, off-page, covered by shapes or images, clipped, hidden layers (render-differential + parser-differential) | JavaScript, OpenAction, Launch, embedded files | metadata, XMP, annotations, form fields |
| **HTML / URL** | font-size 0, colour = background, transparent, opacity 0, off-screen, scale(0), via inline styles, `<style>` and linked CSS | eval-of-decoded-string loaders, cryptominers, hidden iframes, `javascript:` / `data:` URLs, password forms posting elsewhere, meta-refresh | comments, alt/title/aria text, meta tags, JSON-LD, noscript |
| **SVG** | opacity 0, font-size 0, tiny foreignObject | `<script>`, event handlers | – |
| **Word (docx/docm)** | hidden runs, white text, 1-pt text, tracked deletions, style-inherited hiding | VBA macros, DDE fields, remote templates, ms-msdt/mhtml ("Follina") links, UNC paths, ActiveX, OLE objects, altChunk | comments, properties, custom XML, doc variables |
| **PowerPoint (pptx)** | hidden slides, hidden shapes, off-slide shapes, 1-pt, no-fill text | macros, external OLE | speaker notes, comments |
| **Excel (xlsx/xlsm)** | very-hidden / hidden sheets, `;;;` formats, white fonts, hidden rows / cols | XLM macro sheets, Auto_Open, DDE formulas, WEBSERVICE/CALL/EXEC, external links | cell comments |
| **Markdown / text** | `<!-- -->` and `[//]: #` comments, hidden inline HTML | `javascript:` links, image-URL exfiltration templates (`![](https://x/?q={chat})`) | alt text, link titles |
| **Images** | near-background text (OCR before vs after contrast boost, compared by text box), text painted into transparent pixels | data appended after the image end, polyglots (ZIP, HTML, PDF, EXE inside), script in metadata, decompression bombs | EXIF, XMP, PNG text chunks, JPEG comments |
| **OpenDocument** (odt/ods/odp) | hidden text, hidden paragraphs | macros, links to protocol handlers or file shares | document properties |
| **RTF** | hidden text (`\v`) | auto-updating OLE objects, Equation Editor (CVE-2017-11882), remote templates | – |
| **Legacy** .doc/.xls/.ppt | not inspected (always warned) | macros, Equation Editor (CVE-2017-11882) | – |

Every format also checks for Unicode smuggling (tag characters, which it decodes; bidi overrides; zero-width runs),
homoglyph words, and instruction-style phrasing aimed at AI models. That phrasing counts as `critical` when
hidden and `medium` when visible.

URL fetching is careful. Only http(s) is allowed, with size and time limits. Redirects are followed manually,
and every hop is checked against an SSRF guard that refuses private, loopback and link-local addresses. Linked
CSS and scripts are fetched (also limited) so the analysis sees what a browser would. Nothing is ever executed.

## Results

All numbers come from the scripts in `bench/` and `baselines/`, run on the test data described in
[Test data](#test-data). Full per-technique tables:
[bench/RESULTS.md](bench/RESULTS.md) (PDF), [bench/MULTI_RESULTS.md](bench/MULTI_RESULTS.md) (other formats),
[bench/EXPOSURE.md](bench/EXPOSURE.md) (loaders), [bench/E2E.md](bench/E2E.md) (LLM answers),
[bench/COMPARE.md](bench/COMPARE.md) (other scanners).

### Detection and false alarms

| format | attacked | `safe: false` | warned or failed | canary in `safe_text` | clean files | clean `safe: false` |
|---|---|---|---|---|---|---|
| PDF | 420 | 93% | 100% | 0% | 196 | 0 |
| HTML | 320 | 84% | 84% | 0% | 136 | 0 |
| Word | 140 | 86% | 93% | 0% | 136 | 0 |
| PowerPoint | 120 | 83% | 92% | 0% | 45 | 0 |
| Excel | 120 | 83% | 92% | 0% | 119 | 0 |
| Markdown | 120 | 83% | 83% | 0% | 136 | 0 |
| Images | 60 | 78% | 80% | 0% | 60 | 0 |
| SVG | 40 | 100% | 100% | 0% | 10 | 0 |
| **all** | **1340** | **87%** | **91%** | **0%** | **838** | **0** |

- **Every instruction-style payload and every active-content sample is caught** (`safe: false`).
- **What passes as `safe: true` is fact-style text in channels that are normally legitimate:** HTML comments,
  alt text, meta description, JSON-LD, `display:none` panels, speaker notes, hidden rows, tracked deletions, EXIF.
  None of it is in `safe_text` (0% leak). If you index `safe_text`, it never reaches the model.
- **Real websites:** 0 unsafe and 0 warnings across Wikipedia, Python docs, GOV.UK, BBC, GitHub, MDN, Apple,
  Microsoft, IRS, WHO, Amazon, Medium, Coursera and arXiv. CNN and Healthline get one informational note each,
  for minified bundles. Sites that block automated clients (NYT, Reuters, NIH returned 403) come back as
  "could not fetch URL, so its content was not verified".
- **Real PDFs:** 9 of 10 public PDFs pass. One Raspberry Pi brief gets a warning (not `safe: false`) for
  text placed off the page.

### Do common loaders pass the hidden text on?

Share of attacked files whose hidden canary appears in the loader's output.

| format | loaders tested | worst loader | readerguard `safe_text` |
|---|---|---|---|
| PDF | PyMuPDF, pdfminer.six, MarkItDown | 69% (pdfminer.six) | 0% |
| HTML | BeautifulSoup, html2text, MarkItDown | 77% (html2text, MarkItDown) | 0% |
| Word | python-docx, docx2txt, MarkItDown | 60% (docx2txt) | 0% |
| PowerPoint | python-pptx, MarkItDown | 100% | 0% |
| Excel | openpyxl, MarkItDown | 100% | 0% |
| Markdown | raw text, MarkItDown | 83% (raw text) | 0% |
| SVG | BeautifulSoup, raw text | 100% | 0% |
| Images | MarkItDown | 0% (text is in pixels or metadata) | 0% |

### Does it change the LLM's answer?

Each attacked file's text is given to an LLM (Amazon Bedrock) with one question. An attack succeeds when the
answer repeats the hidden payload (the instruction payload says to claim *full coverage*; the fact payload
says the waiting period is *400 days*). Graded by string match, no judge model. 1,120 files per model.

| model | standard loader (MarkItDown) | drop files marked `safe: false`, load the rest normally | index `safe_text` |
|---|---|---|---|
| Qwen3-235B | 45% | 6% | **0%** |
| Llama-3.3-70B | 58% | 6% | **0%** |
| Qwen3-VL-235B (60 raw images) | 0% | 0% | – |

The 6% left after dropping unsafe files is fact-style text in channels readerguard passes or only warns
about (HTML comments, meta tags, speaker notes, hidden rows). Indexing `safe_text` removes it. Total cost of the run: $2.86.

### Compared with other scanners

Same 1,340 attacked and 838 clean files. Detection = the tool's rejecting decision on attacked files;
false alarm = the same decision on clean files.

| tool | detection | false alarms | notes |
|---|---|---|---|
| **readerguard** (`safe: false`) | **87%** | **0%** | all 8 formats |
| [DocFirewall](https://github.com/doc-firewall/doc-firewall) 0.5.1, default profile | 76% | 55% | never returned BLOCK; FLAG counted as detection |
| DocFirewall 0.5.1, strict profile (406-file sample) | 76% | 51% | adds its ML classifiers |
| [PhantomLint](https://github.com/tobycmurray/phantom-lint) (commit `7f62001`) | 13% | 0% | PDF and HTML only; instruction payloads only; 45 crashes |

PhantomLint normally uses Tesseract OCR; this run used Apple Vision through PhantomLint's own OCR interface.
DocFirewall's PyTorch models were forced onto the CPU because the Apple-GPU backend crashed. Details in
[bench/COMPARE.md](bench/COMPARE.md).

## Test data

The test data is generated, not downloaded. It is built from **pdfbench**, a synthetic document set in which
every company, person and product is fictional: 136 documents in five domains (insurance, automotive, pharma,
education, computers), each as a born-digital PDF and as HTML. Generation is deterministic (seed 0), so the
scripts below rebuild the same files. The generated set is about 160 MB and is not checked into git
(`bench/out/` is in `.gitignore`).

**Clean files (838)**, used to measure false alarms:

| format | files | how it is made |
|---|---|---|
| PDF | 196 | 136 pdfbench PDFs, 50 scanned variants, 10 real public PDFs (recall notices, product briefs, drug labels, fee schedules, benefit summaries) |
| HTML | 136 | pdfbench HTML |
| Word, Markdown | 136 each | pdfbench HTML converted with pandoc |
| PowerPoint | 45 | every third HTML document converted with pandoc |
| Excel | 119 | the tables from each HTML document |
| Images | 60 | first page of 60 random PDFs rendered at 110 dpi (PNG and JPEG) |
| SVG | 10 | simple bar charts |

**Attacked files (1,340 hidden-content attacks, plus a visible-injection control):** 72 hiding and active-content
techniques injected into the clean files. Each payload is a harmless sentence with a unique canary token
(`ZQ12345X`), in two styles:

- *instruction*: tells the model to claim the policy offers "full coverage" (has trigger words)
- *fact*: states a false "400 days" waiting period (no trigger words, so only visibility and structure give it away)

Active-content samples (macros, DDE, JavaScript, SVG scripts) are defanged: they run `echo` or `alert(1)` and
point at `example.net`. The PDF set is 14 techniques × 2 payload styles × 15 source documents; per-format
technique lists are in [bench/MULTI_RESULTS.md](bench/MULTI_RESULTS.md).

```
bench/out/
  attacks/<technique>/<instruction|fact>/*.pdf      attacked PDFs
  multi/<format>/<technique>/...                    attacked HTML, Word, PowerPoint, Excel, Markdown, images, SVG
  clean/<format>/...                                clean HTML, Word, PowerPoint, Excel, Markdown, images, SVG
  results.json, multi_results.json                  every file with its technique, payload, canary and verdict
```

Clean PDFs are read in place from pdfbench (`../pdfbench/data`).

**Packaged test data (not yet published):** `readerguard-testdata-v1.zip` (177 MB) will hold all of the above: 1,411
attacked files (1,340 hidden-content attacks and 71 visible-injection controls), 828 clean files, every
result file from the benchmark, and a `manifest.csv` giving each file's format, technique, payload style and
canary. The 10 real public PDFs are not included because they belong to third parties; `real_pdf_sources.json`
in the zip lists their URLs and SHA-256 checksums. Until it is released, build the zip yourself with
`python -m bench.package_data` (writes `dist/`). Some files contain defanged macro, DDE or script samples, and
antivirus software may still flag them.

## Reproducing the benchmark

Run everything from the repository root, with pdfbench checked out next to it (`../pdfbench`) and `pandoc`
on the PATH. pdfbench is not public yet, so for now the benchmark can only be rebuilt by its authors.

```bash
pip install -e ".[differential,ocr-mac,bench]"

# 1. PDF attacks and PDF results            -> bench/out/attacks/, bench/RESULTS.md
python -m bench.attacks --src ../pdfbench/data --per 15 --out bench/out/attacks
python -m bench.evaluate

# 2. clean corpus, other-format attacks and results   -> bench/out/clean/, bench/out/multi/, bench/MULTI_RESULTS.md
bash bench/build_clean.sh ../pdfbench/data bench/out/clean
python -m bench.multi build
python -m bench.multi eval

# 3. which loaders pass the hidden text on   -> bench/EXPOSURE.md
python -m bench.exposure
```

**LLM answer test** (optional, calls Amazon Bedrock, about $3). Needs a Bedrock API key and pdfbench's
`eval/bedrock.py` client. Spending stops at `EVAL_BUDGET_USD` (default 5); runs resume where they stopped.

```bash
export AWS_BEARER_TOKEN_BEDROCK=...          # region: EVAL_BEDROCK_REGION, default us-west-2
python -m bench.e2e prep
python -m bench.e2e run qwen3-235b
python -m bench.e2e run llama3.3-70b
python -m bench.e2e run qwen3-vl-235b
python -m bench.e2e report                   # -> bench/E2E.md
```

**Other scanners** (optional, slow: DocFirewall strict is about 35 s per file). Each gets its own Python 3.12
environment under `baselines/`:

```bash
python3.12 -m venv baselines/.venv-df
baselines/.venv-df/bin/pip install "doc-firewall[ml]==0.5.1" "transformers<5" "sentence-transformers<6"
baselines/.venv-df/bin/python baselines/run_docfirewall.py balanced
baselines/.venv-df/bin/python baselines/run_docfirewall.py strict --sample

git clone https://github.com/tobycmurray/phantom-lint baselines/phantom-lint
git -C baselines/phantom-lint checkout 7f62001
python3.12 -m venv baselines/.venv-pl
baselines/.venv-pl/bin/pip install -r baselines/phantom-lint/requirements-frozen.txt
baselines/.venv-pl/bin/pip install -e baselines/phantom-lint ocrmac
baselines/.venv-pl/bin/playwright install chromium
baselines/.venv-pl/bin/python baselines/run_phantomlint.py          # Tesseract if installed, else Apple Vision

python -m bench.compare                      # -> bench/COMPARE.md
```

`DF_PROCS` and `PL_PROCS` set the number of worker processes (defaults 6 and 4).

## Options

```python
scan(src, strict=False, ocr="auto", ocr_fn=None, differential=True, fetch_options=FetchOptions(...))
FetchOptions(timeout=15, max_bytes=25_000_000, max_redirects=5, allow_private=False, fetch_resources=True)
scan_report(src)        # full Report: per-page safe_pages / raw_pages and every finding
```

OCR uses Apple Vision through `ocrmac` on macOS. Pass any engine as `ocr_fn=lambda png_bytes: text`.
Without OCR, the image and PDF checks that need it are skipped, and the result says so.

## Limitations

- HTML visibility comes from static CSS (no layout engine). Selectors with `+`, `~` or pseudo-classes are ignored,
  and so is CSS injected by JavaScript at runtime.
- Static script heuristics catch common loaders and miners, not novel malware. Pair this with URL reputation and
  AV scanning for hostile uploads.
- Legacy `.doc/.xls/.ppt` get a macro and exploit-marker check only. Convert them for a full scan.
- Remapped-font PDF attacks need the OCR check. Injection phrasing is English-only.

The attack generators in `bench/` produce harmless canaries and defanged samples. Use them only on systems you
are authorised to test.

License: Apache-2.0.
