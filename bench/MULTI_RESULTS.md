# readerguard multi-format evaluation

`unsafe` = `scan()` returned `safe: false`. `flagged` = verdict warn or fail. `leaked` = the canary survived in `safe_text`. Payload `active` = scripts, macros, DDE and similar (defanged), no text payload. `visible_injection` is a baseline: the text is visible, so it is flagged (warn) but kept in safe_text.

| format | technique | n | unsafe: instruction / fact / active | flagged | leaked | main checks |
|---|---|---|---|---|---|---|
| docx | dde_field | 10 | – / – / 100% | 100% | – | dde |
| docx | follina_uri | 10 | – / – / 100% | 100% | – | dangerous_uri |
| docx | macro | 10 | – / – / 100% | 100% | – | macros |
| docx | metadata | 20 | 100% / 0% / – | 100% | 0% | side_channel_text, prompt_injection |
| docx | remote_template | 10 | – / – / 100% | 100% | – | remote_content |
| docx | tiny_font | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| docx | tracked_deletion | 20 | 100% / 0% / – | 50% | 0% | hidden_text, prompt_injection |
| docx | vanish | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| docx | visible_injection | 10 | 0% / – / – | 100% | 100% | prompt_injection |
| docx | white_text | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| html | alt_text | 20 | 100% / 0% / – | 50% | 0% | prompt_injection |
| html | credential_form | 10 | – / – / 100% | 100% | – | credential_form |
| html | cryptominer | 10 | – / – / 100% | 100% | – | malicious_script |
| html | css_class | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| html | display_none | 20 | 100% / 0% / – | 50% | 0% | prompt_injection |
| html | eval_atob_script | 10 | – / – / 100% | 100% | – | malicious_script |
| html | hidden_iframe | 10 | – / – / 100% | 100% | – | hidden_iframe |
| html | html_comment | 20 | 100% / 0% / – | 50% | 0% | prompt_injection |
| html | json_ld | 20 | 100% / 0% / – | 50% | 0% | prompt_injection |
| html | meta_description | 20 | 100% / 0% / – | 50% | 0% | prompt_injection |
| html | meta_refresh_js | 10 | – / – / 100% | 100% | – | meta_refresh |
| html | near_white | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| html | off_screen | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| html | onclick_eval | 10 | – / – / 100% | 100% | – | malicious_script |
| html | opacity_zero | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| html | scale_zero | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| html | tag_smuggling | 20 | 100% / 100% / – | 100% | 0% | unicode_smuggling |
| html | visible_injection | 10 | 0% / – / – | 100% | 100% | prompt_injection |
| html | white_on_white | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| html | zero_font | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| image | appended_zip | 12 | 100% / 100% / – | 100% | 0% | appended_data |
| image | exif_comment | 12 | 100% / 0% / – | 50% | 0% | prompt_injection, side_channel_text |
| image | low_contrast_text | 12 | 100% / 83% / – | 100% | 0% | hidden_text, prompt_injection |
| image | png_text_chunk | 12 | 100% / 0% / – | 50% | 0% | prompt_injection, side_channel_text |
| image | transparent_text | 12 | 100% / 100% / – | 100% | 0% | hidden_pixels, hidden_text |
| image | visible_injection | 6 | 0% / – / – | 100% | 100% | prompt_injection |
| markdown | exfil_image | 10 | 100% / – / – | 100% | 0% | exfiltration_image |
| markdown | hidden_span | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| markdown | html_comment | 20 | 100% / 0% / – | 50% | 0% | prompt_injection, side_channel_text |
| markdown | js_link | 10 | 100% / – / – | 100% | 0% | javascript_url |
| markdown | md_comment | 20 | 100% / 0% / – | 50% | 0% | prompt_injection, side_channel_text |
| markdown | tag_smuggling | 20 | 100% / 100% / – | 100% | 0% | unicode_smuggling |
| markdown | visible_injection | 10 | 0% / – / – | 100% | 100% | prompt_injection |
| markdown | white_span | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| pptx | hidden_shape | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| pptx | hidden_slide | 20 | 100% / 0% / – | 100% | 0% | hidden_text, prompt_injection |
| pptx | no_fill | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| pptx | off_slide | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| pptx | speaker_notes | 20 | 100% / 0% / – | 50% | 0% | prompt_injection |
| pptx | tiny_font | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| pptx | visible_injection | 10 | 0% / – / – | 100% | 100% | prompt_injection |
| svg | svg_foreign_object | 10 | 100% / 100% / – | 100% | 0% | hidden_text, svg_foreign_object |
| svg | svg_hidden_text | 10 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| svg | svg_onload | 5 | 100% / – / – | 100% | – | svg_script |
| svg | svg_script | 5 | 100% / – / – | 100% | – | svg_script |
| svg | svg_zero_font | 10 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| xlsx | dde_formula | 10 | – / – / 100% | 100% | – | dde |
| xlsx | format_hides | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| xlsx | hidden_row | 20 | 100% / 0% / – | 50% | 0% | prompt_injection |
| xlsx | hidden_sheet | 20 | 100% / 0% / – | 100% | 0% | hidden_text, prompt_injection |
| xlsx | very_hidden_sheet | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |
| xlsx | visible_injection | 10 | 0% / – / – | 100% | 100% | prompt_injection |
| xlsx | webservice_formula | 10 | – / – / 100% | 100% | – | dangerous_formula |
| xlsx | white_font | 20 | 100% / 100% / – | 100% | 0% | hidden_text, prompt_injection |

## Per format (attacks excluding the visible-injection baseline)

| format | attacked | unsafe | flagged | leaked | clean files | clean unsafe | clean warn |
|---|---|---|---|---|---|---|---|
| docx | 140 | 86% | 93% | 0% | 136 | 0 | 0 |
| html | 320 | 84% | 84% | 0% | 136 | 0 | 0 |
| image | 60 | 78% | 80% | 0% | 60 | 0 | 0 |
| markdown | 120 | 83% | 83% | 0% | 136 | 0 | 0 |
| pptx | 120 | 83% | 92% | 0% | 45 | 0 | 0 |
| svg | 40 | 100% | 100% | 0% | 10 | 0 | 0 |
| xlsx | 120 | 83% | 92% | 0% | 119 | 0 | 0 |
| **all** | 920 | 84% | 88% | 0% | 642 | 0 | 0 |

Clean files that were not `pass`:


Attacked files judged safe (misses):

- docx / metadata / fact: 10 (verdict warn: success (with warnings): properties.subject holds sentence-length text that does not appear in the visible body)
- docx / tracked_deletion / fact: 10 (verdict pass: success)
- html / alt_text / fact: 10 (verdict pass: success)
- html / display_none / fact: 10 (verdict pass: success)
- html / html_comment / fact: 10 (verdict pass: success)
- html / json_ld / fact: 10 (verdict pass: success)
- html / meta_description / fact: 10 (verdict pass: success)
- image / exif_comment / fact: 6 (verdict pass: success)
- image / low_contrast_text / fact: 1 (verdict warn: success (with warnings): hidden text (low_contrast_or_transparent): 1 piece(s) of text in the image that a parser extracts but a reader cann)
- image / png_text_chunk / fact: 6 (verdict pass: success)
- markdown / html_comment / fact: 10 (verdict pass: success)
- markdown / md_comment / fact: 10 (verdict pass: success)
- pptx / hidden_slide / fact: 10 (verdict warn: success (with warnings): hidden text (hidden_slide): 1 piece(s) of text in pptx that a parser extracts but a reader cannot see: "Revised ter)
- pptx / speaker_notes / fact: 10 (verdict pass: success)
- xlsx / hidden_row / fact: 10 (verdict pass: success)
- xlsx / hidden_sheet / fact: 10 (verdict warn: success (with warnings): hidden text (hidden_sheet): 1 piece(s) of text in xlsx that a parser extracts but a reader cannot see: "Revised ter)
