"""Finding and Report types shared by every check."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def sev_rank(s: str) -> int:
    return _RANK[s]


@dataclass
class Finding:
    check: str                 # e.g. "hidden_text", "javascript", "prompt_injection"
    severity: str              # one of SEVERITIES
    message: str
    page: int | None = None    # 0-based; None for document-level findings
    bbox: tuple | None = None  # page coordinates (unrotated), if any
    reason: str | None = None  # finer-grained cause, e.g. "white_on_white", "covered"
    text: str | None = None    # offending text, truncated

    def to_dict(self) -> dict:
        d = asdict(self)
        if d["bbox"] is not None:
            d["bbox"] = [round(v, 1) for v in d["bbox"]]
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class Report:
    path: str
    format: str = "unknown"
    pages: int = 0
    findings: list[Finding] = field(default_factory=list)
    safe_pages: list[str] = field(default_factory=list)   # visible-only text per page
    raw_pages: list[str] = field(default_factory=list)    # what a naive text-layer parser sees
    error: str | None = None

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max((f.severity for f in self.findings), key=sev_rank)

    @property
    def verdict(self) -> str:
        """pass / warn / fail, for use as an ingestion gate."""
        if self.error:
            return "fail"
        r = sev_rank(self.max_severity)
        if r >= sev_rank("high"):
            return "fail"
        if r >= sev_rank("medium"):
            return "warn"
        return "pass"

    @property
    def safe_text(self) -> str:
        from .textscan import strip_invisible
        return strip_invisible("\n\f".join(self.safe_pages))

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.check] = counts.get(f.check, 0) + 1
        return {"path": self.path, "format": self.format, "verdict": self.verdict, "max_severity": self.max_severity,
                "pages": self.pages, "counts": counts, "error": self.error}

    def to_dict(self, include_text: bool = False) -> dict:
        d = self.summary()
        d["findings"] = [f.to_dict() for f in self.findings]
        if include_text:
            d["safe_pages"] = self.safe_pages
        return d


def clip(s: str, n: int = 160) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"
