"""Just enough CSS to decide whether text is visible: rule parsing, selector matching (type, class, id,
attribute, descendant and child combinators), colours, lengths. No layout engine, so this is an approximation.
Rules with pseudo-classes (:hover, :focus...) are interaction states and are skipped."""
from __future__ import annotations

import re

RELEVANT = {"display", "visibility", "opacity", "font-size", "color", "background", "background-color", "position",
            "left", "top", "right", "bottom", "text-indent", "clip", "clip-path", "height", "max-height", "width",
            "max-width", "overflow", "transform", "fill", "fill-opacity", "font", "background-clip",
            "-webkit-background-clip", "-webkit-text-fill-color"}

NAMED = {
    "white": (255, 255, 255), "black": (0, 0, 0), "red": (255, 0, 0), "green": (0, 128, 0), "blue": (0, 0, 255),
    "gray": (128, 128, 128), "grey": (128, 128, 128), "silver": (192, 192, 192), "whitesmoke": (245, 245, 245),
    "snow": (255, 250, 250), "ivory": (255, 255, 240), "ghostwhite": (248, 248, 255), "azure": (240, 255, 255),
    "aliceblue": (240, 248, 255), "mintcream": (245, 255, 250), "seashell": (255, 245, 238), "linen": (250, 240, 230),
    "floralwhite": (255, 250, 240), "honeydew": (240, 255, 240), "lightgray": (211, 211, 211),
    "lightgrey": (211, 211, 211), "gainsboro": (220, 220, 220), "yellow": (255, 255, 0), "navy": (0, 0, 128),
    "beige": (245, 245, 220), "lavender": (230, 230, 250), "lightyellow": (255, 255, 224),
}


def parse_color(v: str):
    """-> (r, g, b, alpha) in 0..255 / 0..1, or None when unknown (var(), gradients, currentColor...)."""
    v = v.strip().lower()
    if not v or "var(" in v or "gradient" in v or "url(" in v:
        return None
    if v == "transparent":
        return (0, 0, 0, 0.0)
    m = re.fullmatch(r"#([0-9a-f]{3,8})", v)
    if m:
        h = m.group(1)
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        if len(h) not in (6, 8):
            return None
        a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), a)
    m = re.fullmatch(r"rgba?\(([^)]*)\)", v)
    if m:
        parts = [p for p in re.split(r"[\s,/]+", m.group(1)) if p]
        try:
            rgb = [float(p[:-1]) * 2.55 if p.endswith("%") else float(p) for p in parts[:3]]
            a = parts[3] if len(parts) > 3 else "1"
            a = float(a[:-1]) / 100 if a.endswith("%") else float(a)
            return (*[int(max(0, min(255, x))) for x in rgb], a)
        except (ValueError, IndexError):
            return None
    if v in NAMED:
        return (*NAMED[v], 1.0)
    return None


def first_color(v: str):
    """background shorthand: pick the first colour-looking token."""
    if parse_color(v):
        return parse_color(v)
    for tok in re.findall(r"#[0-9a-fA-F]{3,8}|rgba?\([^)]*\)|\b[a-z]+\b", v):
        c = parse_color(tok)
        if c:
            return c
    return None


def length_px(v: str, base: float = 16.0):
    """CSS length in px (approximate), or None."""
    v = v.strip().lower()
    m = re.match(r"^(-?[\d.]+)(px|pt|em|rem|%|vw|vh|ch|ex)?$", v)
    if not m:
        return None
    n, u = float(m.group(1)), m.group(2) or "px"
    return {"px": n, "pt": n * 4 / 3, "em": n * base, "rem": n * 16, "%": n * base / 100, "ch": n * base / 2,
            "ex": n * base / 2, "vw": n * 12, "vh": n * 8}[u]


def parse_decls(s: str) -> dict:
    out = {}
    for part in s.split(";"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k = k.strip().lower()
        v = re.sub(r"!\s*important", "", v).strip()
        if k:
            out[k] = v
    return out


_COMPOUND = re.compile(r"^(?P<tag>[a-zA-Z][\w-]*|\*)?(?P<rest>(?:[#.][\w-]+|\[[^\]]+\])*)$")


class Compound:
    __slots__ = ("tag", "ids", "classes", "attrs")

    def __init__(self, tag, ids, classes, attrs):
        self.tag, self.ids, self.classes, self.attrs = tag, ids, classes, attrs

    def match(self, node) -> bool:
        if self.tag and self.tag != "*" and node.tag != self.tag:
            return False
        a = node.attrs
        if self.ids and a.get("id") not in self.ids:
            return False
        if self.classes and not self.classes <= node.classes:
            return False
        for name, val in self.attrs:
            if name not in a or (val is not None and a[name] != val):
                return False
        return True


def parse_compound(s: str):
    m = _COMPOUND.match(s)
    if not m:
        return None
    rest = m.group("rest")
    ids = set(re.findall(r"#([\w-]+)", rest))
    classes = set(re.findall(r"\.([\w-]+)", rest))
    attrs = []
    for body in re.findall(r"\[([^\]]+)\]", rest):
        mm = re.match(r"^\s*([\w-]+)\s*(?:=\s*['\"]?([^'\"]*)['\"]?)?\s*$", body)
        if not mm:
            return None
        attrs.append((mm.group(1).lower(), mm.group(2)))
    return Compound((m.group("tag") or "").lower() or None, ids, classes, attrs)


class Selector:
    """Right-to-left chain: parts[-1] matches the node, earlier parts match ancestors."""
    __slots__ = ("parts", "combs")

    def __init__(self, parts, combs):
        self.parts, self.combs = parts, combs

    @property
    def key(self):
        last = self.parts[-1]
        if last.ids:
            return ("id", next(iter(last.ids)))
        if last.classes:
            return ("class", next(iter(last.classes)))
        if last.tag and last.tag != "*":
            return ("tag", last.tag)
        return ("any", "")

    def match(self, node) -> bool:
        if not self.parts[-1].match(node):
            return False
        cur = node
        for i in range(len(self.parts) - 2, -1, -1):
            comp, comb = self.parts[i], self.combs[i]
            if comb == ">":
                cur = cur.parent
                if cur is None or not comp.match(cur):
                    return False
            else:
                cur = cur.parent
                while cur is not None and not comp.match(cur):
                    cur = cur.parent
                if cur is None:
                    return False
        return True


def parse_selector(s: str):
    s = s.strip()
    if not s or ":" in s or "+" in s or "~" in s:
        return None
    toks = re.split(r"\s*(>)\s*|\s+", s)
    parts, combs, pending = [], [], " "
    for t in toks:
        if t is None or t == "":
            continue
        if t == ">":
            pending = ">"
            continue
        c = parse_compound(t)
        if c is None:
            return None
        if parts:
            combs.append(pending)
        parts.append(c)
        pending = " "
    return Selector(parts, combs) if parts else None


def _flatten(css: str) -> str:
    """Drop comments and @-blocks, but keep the contents of @media all / screen without conditions."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    out, i = [], 0
    while i < len(css):
        j = css.find("@", i)
        if j < 0:
            out.append(css[i:])
            break
        out.append(css[i:j])
        brace, semi = css.find("{", j), css.find(";", j)
        if brace < 0 or (0 <= semi < brace):
            i = (semi + 1) if semi >= 0 else len(css)
            continue
        depth, k = 0, brace
        while k < len(css):
            if css[k] == "{":
                depth += 1
            elif css[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        head = css[j:brace].strip().lower()
        if re.fullmatch(r"@media\s+(only\s+)?(all|screen)", head):
            out.append(_flatten(css[brace + 1:k]))
        i = k + 1
    return "".join(out)


def parse_stylesheet(css: str) -> list[tuple[Selector, dict]]:
    rules = []
    for sels, body in re.findall(r"([^{}]+)\{([^{}]*)\}", _flatten(css)):
        decls = {k: v for k, v in parse_decls(body).items() if k in RELEVANT}
        if not decls:
            continue
        for s in sels.split(","):
            sel = parse_selector(s)
            if sel is not None:
                rules.append((sel, decls))
    return rules


class RuleIndex:
    def __init__(self, rules):
        self.by = {}
        for order, (sel, decls) in enumerate(rules):
            self.by.setdefault(sel.key, []).append((order, sel, decls))

    def styles_for(self, node) -> dict:
        cands = list(self.by.get(("any", ""), []))
        cands += self.by.get(("tag", node.tag), [])
        if node.attrs.get("id"):
            cands += self.by.get(("id", node.attrs["id"]), [])
        for c in node.classes:
            cands += self.by.get(("class", c), [])
        out = {}
        for _, sel, decls in sorted(cands, key=lambda x: x[0]):
            if sel.match(node):
                out.update(decls)
        return out
