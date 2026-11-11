"""Content checks that run on any extracted string: Unicode smuggling and prompt-injection phrasing.

These are deliberately conservative. A hidden span is reported by the visibility check whatever it
says; the phrase list only raises severity, and catches injections that are fully visible.
"""
from __future__ import annotations

import re
import unicodedata

TAG_CHARS = (0xE0000, 0xE007F)          # "ASCII smuggling": invisible copies of ASCII
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
PUA = (0xE000, 0xF8FF)

_INJECTION = [
    r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any|other)\b.{0,30}"
    r"\b(instructions?|prompts?|context|rules|directions)\b",
    r"\b(note|message|instructions?|directive)s?\s+(to|for)\s+(the\s+)?(ai|assistant|llm|model|chat ?bot|language model|"
    r"agent|copilot|gpt|claude|gemini)\b",
    r"\b(you are|act as|pretend to be|from now on,? you)\b.{0,30}\b(ai|assistant|chat ?bot|model|agent)\b",
    r"\bsystem\s*prompt\b|\bdeveloper\s+message\b|\bjailbreak\b",
    r"\bdo not\s+(tell|mention|reveal|inform|disclose to)\s+(this\s+to\s+)?(the\s+)?(user|reader|customer)\b",
    r"\b(when|if)\s+(asked|questioned)\b.{0,60}\b(answer|respond|reply|say)\b",
    r"\b(always|only)\s+(answer|respond|reply)\s+(with|that)\b",
    r"<\|?(im_start|im_end|system|endoftext)\|?>|\[/?INST\]|^#{2,}\s*(system|instruction)s?\b",
    r"\b(ai|llm|assistant|model)s?\s+(reading|processing|summari[sz]ing)\s+this\b",
]
INJECTION_RE = [re.compile(p, re.I | re.M | re.S) for p in _INJECTION]


def injection_hits(text: str) -> list[str]:
    t = unicodedata.normalize("NFKC", text)
    hits = []
    for rx in INJECTION_RE:
        m = rx.search(t)
        if m:
            hits.append(m.group(0))
    return hits


def unicode_anomalies(text: str) -> dict:
    """Counts of suspicious code points, plus the decoded payload of any tag characters."""
    tags, zw, bidi, pua = [], 0, 0, 0
    for ch in text:
        o = ord(ch)
        if TAG_CHARS[0] <= o <= TAG_CHARS[1]:
            tags.append(chr(o - 0xE0000) if 0x20 <= o - 0xE0000 < 0x7F else "")
        elif o in ZERO_WIDTH:
            zw += 1
        elif o in BIDI:
            bidi += 1
        elif PUA[0] <= o <= PUA[1]:
            pua += 1
    return {"tag_chars": len(tags), "tag_payload": "".join(tags), "zero_width": zw, "bidi": bidi, "pua": pua}


_INVISIBLE = re.compile("[\U000E0000-\U000E007F\u202A-\u202E\u2066-\u2069\u200B\u200C\u2060\uFEFF\u180E]")


def strip_invisible(text: str) -> str:
    """Remove tag characters, bidi controls and zero-width characters (ZWJ is kept for emoji sequences)."""
    return _INVISIBLE.sub("", text)


_WORD = re.compile(r"[^\W\d_]{3,}", re.U)


def mixed_script_words(text: str, limit: int = 5) -> list[str]:
    """Words that mix Latin with Cyrillic/Greek letters (homoglyph spoofing, e.g. 'pаssword')."""
    out = []
    for w in _WORD.findall(text):
        scripts = set()
        for ch in w:
            name = unicodedata.name(ch, "")
            if name.startswith("LATIN"):
                scripts.add("L")
            elif name.startswith("CYRILLIC"):
                scripts.add("C")
            elif name.startswith("GREEK"):
                scripts.add("G")
        if "L" in scripts and len(scripts) > 1:
            out.append(w)
            if len(out) >= limit:
                break
    return out


_TOKEN = re.compile(r"[a-z0-9]{3,}")


def tokens(text: str) -> list[str]:
    return _TOKEN.findall(unicodedata.normalize("NFKC", text).lower())
