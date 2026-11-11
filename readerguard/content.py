"""Content checks shared by every format: Unicode smuggling, homoglyphs, injection phrasing, and
"side-channel" text (metadata, comments, alt text...) that a reader never sees but a loader may index."""
from __future__ import annotations

from . import textscan
from .findings import Finding, clip

META_PROSE_MIN_TOKENS = 8


def content_findings(text: str, channel: str, page=None, hidden: bool = False,
                     side_channel: str | None = None) -> list[Finding]:
    """hidden: the text is not shown to a human reader (raises injection severity to critical).
    side_channel: "high" / "low" to also report the mere presence of text in this channel."""
    out: list[Finding] = []
    if not text or not text.strip():
        return out
    u = textscan.unicode_anomalies(text)
    if u["tag_chars"]:
        out.append(Finding(check="unicode_smuggling", severity="critical", page=page, reason="tag_chars",
                           text=clip(u["tag_payload"]),
                           message=f"{u['tag_chars']} invisible Unicode tag characters in {channel}"))
    if u["bidi"]:
        out.append(Finding(check="unicode_smuggling", severity="high", page=page, reason="bidi_override",
                           message=f"{u['bidi']} bidirectional control characters in {channel}"))
    if u["zero_width"] >= 5:
        out.append(Finding(check="unicode_smuggling", severity="medium", page=page, reason="zero_width",
                           message=f"{u['zero_width']} zero-width characters in {channel}"))
    mixed = textscan.mixed_script_words(text)
    if mixed:
        out.append(Finding(check="homoglyphs", severity="low" if hidden else "medium", page=page, text=clip(", ".join(mixed)),
                           message=f"words mixing Latin with Cyrillic/Greek letters in {channel}"))
    hits = textscan.injection_hits(text)
    if hits:
        out.append(Finding(check="prompt_injection", severity="critical" if hidden else "medium", page=page,
                           reason=channel, text=clip(" | ".join(hits)),
                           message=f"instruction-like text aimed at an AI model in {channel}"))
    elif side_channel and sum(c.isalnum() for c in text) >= 3:
        out.append(Finding(check="side_channel_text", severity=side_channel, page=page, reason=channel,
                           text=clip(text), message=f"text in {channel} (not part of the visible body)"))
    return out


def novel_prose(text: str, body_tokens: set, channel: str) -> list[Finding]:
    """Sentence-length text in a metadata-like field that does not appear in the visible body."""
    tk = textscan.tokens(text)
    novel = [t for t in tk if t not in body_tokens]
    if len(tk) >= META_PROSE_MIN_TOKENS and len(novel) >= 0.5 * len(tk):
        return [Finding(check="side_channel_text", severity="medium", reason=channel, text=clip(text),
                        message=f"{channel} holds sentence-length text that does not appear in the visible body")]
    return []


def hidden_text_finding(text: str, channel: str, reason: str, page=None, count: int = 1,
                        fragment: str = "medium") -> list[Finding]:
    """A run of text that is extracted but not shown. Sentence length -> high, fragment -> `fragment`."""
    n = sum(c.isalnum() for c in text)
    if n < 3:
        return []
    sev = "high" if n >= 40 else fragment
    return [Finding(check="hidden_text", severity=sev, page=page, reason=reason, text=clip(text),
                    message=f"hidden text ({reason}): {count} piece(s) of text in {channel} that a parser "
                            "extracts but a reader cannot see")]
