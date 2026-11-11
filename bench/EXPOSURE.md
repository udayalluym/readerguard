# Loader exposure

Share of attacked files whose hidden canary appears in each loader's output (visible-injection baseline excluded).

## html

| technique | n | BeautifulSoup | html2text | MarkItDown | readerguard safe_text |
|---|---|---|---|---|---|
| alt_text | 20 | 0% | 100% | 100% | 0% |
| css_class | 20 | 100% | 100% | 100% | 0% |
| display_none | 20 | 100% | 100% | 100% | 0% |
| html_comment | 20 | 0% | 0% | 0% | 0% |
| json_ld | 20 | 0% | 0% | 0% | 0% |
| meta_description | 20 | 0% | 0% | 0% | 0% |
| near_white | 20 | 100% | 100% | 100% | 0% |
| off_screen | 20 | 100% | 100% | 100% | 0% |
| opacity_zero | 20 | 100% | 100% | 100% | 0% |
| scale_zero | 20 | 100% | 100% | 100% | 0% |
| tag_smuggling | 20 | 100% | 100% | 100% | 0% |
| white_on_white | 20 | 100% | 100% | 100% | 0% |
| zero_font | 20 | 100% | 100% | 100% | 0% |
| **all** | 260 | **69%** | **77%** | **77%** | **0%** |

## docx

| technique | n | python-docx | docx2txt | MarkItDown | readerguard safe_text |
|---|---|---|---|---|---|
| metadata | 20 | 0% | 0% | 0% | 0% |
| tiny_font | 20 | 100% | 100% | 100% | 0% |
| tracked_deletion | 20 | 0% | 0% | 0% | 0% |
| vanish | 20 | 95% | 100% | 95% | 0% |
| white_text | 20 | 100% | 100% | 100% | 0% |
| **all** | 100 | **59%** | **60%** | **59%** | **0%** |

## pptx

| technique | n | python-pptx | MarkItDown | readerguard safe_text |
|---|---|---|---|---|
| hidden_shape | 20 | 100% | 100% | 0% |
| hidden_slide | 20 | 100% | 100% | 0% |
| no_fill | 20 | 100% | 100% | 0% |
| off_slide | 20 | 100% | 100% | 0% |
| speaker_notes | 20 | 100% | 100% | 0% |
| tiny_font | 20 | 100% | 100% | 0% |
| **all** | 120 | **100%** | **100%** | **0%** |

## xlsx

| technique | n | openpyxl | MarkItDown | readerguard safe_text |
|---|---|---|---|---|
| format_hides | 20 | 100% | 100% | 0% |
| hidden_row | 20 | 100% | 100% | 0% |
| hidden_sheet | 20 | 100% | 100% | 0% |
| very_hidden_sheet | 20 | 100% | 100% | 0% |
| white_font | 20 | 100% | 100% | 0% |
| **all** | 100 | **100%** | **100%** | **0%** |

## markdown

| technique | n | raw text | MarkItDown | readerguard safe_text |
|---|---|---|---|---|
| exfil_image | 10 | 0% | 0% | 0% |
| hidden_span | 20 | 100% | 100% | 0% |
| html_comment | 20 | 100% | 100% | 0% |
| js_link | 10 | 0% | 0% | 0% |
| md_comment | 20 | 100% | 100% | 0% |
| tag_smuggling | 20 | 100% | 85% | 0% |
| white_span | 20 | 100% | 100% | 0% |
| **all** | 120 | **83%** | **81%** | **0%** |

## image

| technique | n | MarkItDown | readerguard safe_text |
|---|---|---|---|
| appended_zip | 12 | 0% | 0% |
| exif_comment | 12 | 0% | 0% |
| low_contrast_text | 12 | 0% | 0% |
| png_text_chunk | 12 | 0% | 0% |
| transparent_text | 12 | 0% | 0% |
| **all** | 60 | **0%** | **0%** |

## svg

| technique | n | BeautifulSoup | raw text | readerguard safe_text |
|---|---|---|---|---|
| svg_foreign_object | 10 | 100% | 100% | 0% |
| svg_hidden_text | 10 | 100% | 100% | 0% |
| svg_zero_font | 10 | 100% | 100% | 0% |
| **all** | 30 | **100%** | **100%** | **0%** |

## pdf

| technique | n | PyMuPDF | pdfminer.six | MarkItDown | readerguard safe_text |
|---|---|---|---|---|---|
| behind_image | 30 | 100% | 100% | 100% | 0% |
| clipped | 30 | 0% | 100% | 93% | 0% |
| covered_shape | 30 | 100% | 100% | 97% | 0% |
| embedded_file | 30 | 0% | 0% | 0% | 0% |
| hidden_annotation | 30 | 0% | 0% | 0% | 0% |
| hidden_layer | 30 | 0% | 100% | 93% | 0% |
| invisible_mode | 30 | 100% | 100% | 100% | 0% |
| metadata | 30 | 0% | 0% | 0% | 0% |
| near_white | 30 | 100% | 100% | 93% | 0% |
| off_page | 30 | 0% | 100% | 100% | 0% |
| tag_smuggling | 30 | 0% | 0% | 0% | 0% |
| tiny_font | 30 | 100% | 100% | 100% | 0% |
| white_text | 30 | 100% | 100% | 97% | 0% |
| **all** | 390 | **46%** | **69%** | **67%** | **0%** |

