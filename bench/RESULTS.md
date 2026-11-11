# readerguard PDF evaluation

435 attacked PDFs: 15 techniques × 2 payload styles (instruction / fact) × 15 source documents from pdfbench (`visible_injection` has only the instruction style). Every payload carries a unique canary token.

**Exposed** = the canary is in that parser's output (what a naive loader indexes). **Side** = metadata, annotations or attachments, which many loaders copy into chunk metadata. **Blocked** = verdict `fail`; **flagged** = `warn` or `fail`. **Leaked** = the canary survives in `safe_text`.

| technique | n | exposed PyMuPDF | exposed pdfminer | exposed pdfplumber | exposed side | flagged | blocked | leaked | main checks |
|---|---|---|---|---|---|---|---|---|---|
| white_text | 30 | 100% | 100% | 93% | 0% | 100% | 100% | 0% | hidden_text, prompt_injection |
| near_white | 30 | 100% | 100% | 90% | 0% | 100% | 100% | 0% | hidden_text, prompt_injection |
| invisible_mode | 30 | 100% | 100% | 100% | 0% | 100% | 100% | 0% | hidden_text, prompt_injection |
| tiny_font | 30 | 100% | 100% | 93% | 0% | 100% | 100% | 0% | hidden_text, prompt_injection |
| off_page | 30 | 0% | 100% | 100% | 0% | 100% | 100% | 0% | hidden_text, prompt_injection |
| covered_shape | 30 | 100% | 100% | 93% | 0% | 100% | 100% | 0% | hidden_text, prompt_injection |
| behind_image | 30 | 100% | 100% | 97% | 0% | 100% | 100% | 0% | hidden_text, prompt_injection |
| hidden_layer | 30 | 0% | 100% | 90% | 0% | 100% | 100% | 0% | hidden_layer, parser_differential |
| clipped | 30 | 0% | 100% | 90% | 0% | 100% | 100% | 0% | hidden_text, prompt_injection |
| hidden_annotation | 30 | 0% | 0% | 0% | 100% | 100% | 100% | 0% | prompt_injection, side_channel_text |
| metadata | 30 | 0% | 0% | 0% | 100% | 100% | 50% | 0% | side_channel_text, prompt_injection |
| tag_smuggling | 30 | 0% | 0% | 0% | 100% | 100% | 100% | 0% | unicode_smuggling |
| embedded_file | 30 | 0% | 0% | 0% | 100% | 100% | 50% | 0% | embedded_file, prompt_injection |
| javascript | 30 | 0% | 0% | 0% | 0% | 100% | 100% | 0% | javascript, open_action |
| visible_injection | 15 | 100% | 100% | 93% | 0% | 100% | 0% | 100% | prompt_injection |

**Hidden techniques overall** (420 PDFs): flagged 100%, blocked 93%, canary leaked into safe text 0%; 93% of them expose the canary to at least one parser or loader channel.

Blocked by payload style (hidden techniques): instruction 100%, fact 86%. The fact-style payload has no trigger words, so detection there comes from visibility and structure alone.

## Clean documents (false positives)

| set | PDFs | pages | pass | warn | fail | safe-text token retention | s/page |
|---|---|---|---|---|---|---|---|
| pdfbench born-digital (attack sources) | 136 | 276 | 136 | 0 | 0 | 100.00% | 0.06 |
| pdfbench as released (incl. scanned docs) | 136 | 276 | 136 | 0 | 0 | 100.00% | 0.05 |
| pdfbench scanned variants (mp_c5_on) | 50 | 200 | 50 | 0 | 0 | – (no text layer) | 0.00 |
| real public PDFs | 10 | 90 | 9 | 1 | 0 | 100.00% | 0.12 |

Non-pass clean documents:

- `comp_rpi4_brief.pdf` (real public PDFs) **warn**: hidden_text/off_page: Raspberry Pi 4 Model B Safety warnings 5
