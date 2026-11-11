"""HTML (and SVG): hidden text, side-channel text, and malicious or suspicious scripts.

Static analysis only: nothing is executed. Visibility comes from inline styles, <style> blocks, linked
stylesheets (when a resource fetcher is supplied, e.g. for URL scans) and SVG presentation attributes.

Hidden text falls into three classes:
  stealth    font-size 0, transparent / same-as-background colour, off-screen, scale(0): the classic tricks
             for showing text to crawlers and LLMs but not to people. Sentence length -> high.
  collapsed  display:none, visibility:hidden, [hidden], <template>: menus, tabs, modals; common and
             usually legitimate. Reported only when it carries an injection or a lot of prose.
  sr_only    the 1px "screen-reader only" accessibility pattern. Low.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from ..content import content_findings, hidden_text_finding
from ..findings import Finding, Report, clip
from ..pdf.visibility import contrast
from . import css as C

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
AUTOCLOSE = {"p": {"p", "div", "ul", "ol", "table", "h1", "h2", "h3", "h4", "h5", "h6", "section"},
             "li": {"li"}, "option": {"option"}, "td": {"td", "th", "tr"}, "th": {"td", "th", "tr"},
             "tr": {"tr"}, "dt": {"dt", "dd"}, "dd": {"dt", "dd"}}
BLOCK = {"p", "div", "section", "article", "header", "footer", "main", "aside", "nav", "li", "ul", "ol", "table",
         "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "br", "hr", "blockquote", "pre", "dl", "dt", "dd",
         "figure", "figcaption", "form", "fieldset", "address", "title", "text", "tspan", "caption"}
EXEC_EXT = re.compile(r"\.(exe|scr|msi|bat|cmd|com|ps1|vbs|js|jse|wsf|hta|jar|apk|dmg|pkg|app|deb|rpm|sh|lnk|iso|"
                      r"dll|cpl|msix|appx)(\?|#|$)", re.I)
SIDE_ATTRS = ("alt", "title", "aria-label", "aria-description", "placeholder", "data-content")


class Node:
    __slots__ = ("tag", "attrs", "children", "parent", "classes")

    def __init__(self, tag, attrs, parent):
        self.tag, self.parent, self.children = tag, parent, []
        self.attrs = {k.lower(): (v if v is not None else "") for k, v in attrs}
        self.classes = set(self.attrs.get("class", "").split())


class _Builder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", [], None)
        self.stack = [self.root]
        self.comments: list[str] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        closers = {t for t, trig in AUTOCLOSE.items() if tag in trig}
        while len(self.stack) > 1 and self.stack[-1].tag in closers:
            self.stack.pop()
        n = Node(tag, attrs, self.stack[-1])
        self.stack[-1].children.append(n)
        if tag not in VOID:
            self.stack.append(n)

    def handle_startendtag(self, tag, attrs):
        n = Node(tag.lower(), attrs, self.stack[-1])
        self.stack[-1].children.append(n)

    def handle_endtag(self, tag):
        tag = tag.lower()
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        if data:
            self.stack[-1].children.append(data)

    def handle_comment(self, data):
        self.comments.append(data)


def parse(html: str):
    b = _Builder()
    try:
        b.feed(html)
        b.close()
    except Exception:
        pass
    return b.root, b.comments


def iter_nodes(root):
    st = [root]
    while st:
        n = st.pop()
        yield n
        st.extend(c for c in reversed(n.children) if isinstance(c, Node))


def node_text(n) -> str:
    out, st = [], [n]
    while st:
        x = st.pop()
        if isinstance(x, str):
            out.append(x)
        else:
            st.extend(reversed(x.children))
    return "".join(out)


# --------------------------------------------------------------------------- scripts

JS_RULES = [
    (re.compile(r"\b(eval|Function)\s*\(\s*(window\.)?(atob|unescape|decodeURIComponent|escape|String\.fromCharCode)\b"),
     "high", "eval_decoded", "evaluates a decoded string (classic loader obfuscation)"),
    (re.compile(r"document\.write(ln)?\s*\(\s*(unescape|atob|decodeURIComponent|String\.fromCharCode)"),
     "high", "write_decoded", "writes decoded markup into the page"),
    (re.compile(r"coinhive|coin-hive|cryptonight|coinimp|webminepool|crypto-?loot|deepminer|\.startMining\s*\(|"
                r"CoinHive\.|minero\.cc|jsecoin", re.I),
     "critical", "cryptominer", "cryptocurrency-miner signature"),
    (re.compile(r"String\.fromCharCode\s*\((\s*\d+\s*,){60,}"), "medium", "charcode_obfuscation",
     "long String.fromCharCode chain"),
    (re.compile(r"['\"][A-Za-z0-9+/]{3000,}={0,2}['\"]"), "low", "encoded_blob", "large base64 blob in a script"),
    (re.compile(r"(?:location(?:\.href)?|window\.location)\s*=\s*['\"](?:data:|https?://\d{1,3}(?:\.\d{1,3}){3})"),
     "medium", "suspicious_redirect", "redirects to a data: URL or a raw IP address"),
]
OBF_ID = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
HEX_ESC = re.compile(r"\\x[0-9a-fA-F]{2}")


def js_findings(code: str, where: str) -> list[Finding]:
    out = []
    for rx, sev, reason, msg in JS_RULES:
        m = rx.search(code)
        if m:
            out.append(Finding(check="malicious_script" if sev in ("high", "critical") else "suspicious_script",
                               severity=sev, reason=reason, text=clip(m.group(0), 100), message=f"{msg} in {where}"))
    if len(OBF_ID.findall(code)) >= 25:
        out.append(Finding(check="suspicious_script", severity="medium", reason="obfuscated_identifiers",
                           message=f"obfuscator-style identifiers (_0x...) in {where}"))
    if len(HEX_ESC.findall(code)) >= 300:
        out.append(Finding(check="suspicious_script", severity="low", reason="hex_escapes",
                           message=f"heavily hex-escaped strings in {where}"))
    return out


# --------------------------------------------------------------------------- visibility


class _State:
    __slots__ = ("collapsed", "stealth", "sr_only", "opacity", "font", "color", "bg", "visibility", "clip_text",
                 "interactive")

    def __init__(self):
        self.collapsed = self.stealth = self.sr_only = None
        self.opacity, self.font = 1.0, 16.0
        self.color = (0, 0, 0, 1.0)
        self.bg = "default"          # "default" (white), "unknown", or an rgba tuple
        self.visibility = "visible"
        self.clip_text = False       # background-clip: text (gradient text): transparent colour is intended
        self.interactive = False     # inside a/button: backgrounds often come from selectors we cannot match

    def child(self):
        s = _State.__new__(_State)
        for k in _State.__slots__:
            setattr(s, k, getattr(self, k))
        return s


SVG_PRES = {"fill": "fill", "opacity": "opacity", "fill-opacity": "fill-opacity", "font-size": "font-size",
            "display": "display", "visibility": "visibility"}


def _apply(st: _State, node: Node, decl: dict, in_svg: bool) -> None:
    if "hidden" in node.attrs and node.tag not in ("input",):
        st.collapsed = st.collapsed or "hidden_attribute"
    if node.tag == "template":
        st.collapsed = st.collapsed or "template"
    d = decl.get("display", "").lower()
    if d == "none":
        st.collapsed = st.collapsed or "display_none"
    v = decl.get("visibility", "").lower()
    if v in ("hidden", "collapse", "visible"):
        st.visibility = v
    for k in ("opacity", "fill-opacity"):
        if k in decl:
            try:
                val = decl[k].strip()
                st.opacity *= float(val[:-1]) / 100 if val.endswith("%") else float(val)
            except ValueError:
                pass
    fs = decl.get("font-size")
    if fs is None and "font" in decl:
        m = re.search(r"(-?[\d.]+(?:px|pt|em|rem|%))", decl["font"])
        fs = m.group(1) if m else None
    if fs:
        px = C.length_px(fs, st.font)
        if px is not None:
            st.font = px
    col = decl.get("fill" if in_svg and "fill" in decl else "color")
    if col:
        if col.strip().lower() in ("inherit", "currentcolor"):
            pass
        elif col.strip().lower() == "none" and in_svg:
            st.color = (0, 0, 0, 0.0)
        else:
            st.color = C.parse_color(col)
    bgv = decl.get("background-color") or decl.get("background")
    if bgv and not in_svg:
        c = C.first_color(bgv)
        if c is None:
            if bgv.strip().lower() not in ("none", "inherit", "initial", "unset"):
                st.bg = "unknown"
        elif c[3] >= 0.5:
            st.bg = c
    if "text" in (decl.get("background-clip", "") + decl.get("-webkit-background-clip", "")).lower():
        st.clip_text = True
    tf = decl.get("-webkit-text-fill-color")
    if tf and not st.clip_text:
        c = C.parse_color(tf)
        if c is not None and c[3] <= 0.05:
            st.color = c
    if node.tag in ("a", "button", "summary", "label", "select") or node.attrs.get("role") in ("button", "tab", "link"):
        st.interactive = True
    pos = decl.get("position", "").lower()
    if pos in ("absolute", "fixed"):
        for k in ("left", "top", "right", "bottom"):
            px = C.length_px(decl.get(k, "x"), st.font)
            if px is not None and px <= -500:
                st.stealth = st.stealth or "off_screen"
    ti = C.length_px(decl.get("text-indent", "x"), st.font)
    if ti is not None and ti <= -500:
        st.stealth = st.stealth or "off_screen"
    tr = decl.get("transform", "")
    if in_svg and node.tag == "foreignobject":
        dims = [C.length_px(node.attrs.get(k, "x")) for k in ("width", "height")]
        if any(d is not None and d <= 20 for d in dims):
            st.stealth = st.stealth or "tiny_foreign_object"
    m = re.search(r"scale[xy]?\(\s*([\d.]+)", tr)
    if m and float(m.group(1)) <= 0.05:
        st.stealth = st.stealth or "scaled_to_zero"
    clipv = (decl.get("clip", "") + " " + decl.get("clip-path", "")).lower()
    tiny_box = any((C.length_px(decl.get(k, "x"), st.font) or 99) <= 1 for k in ("width", "height"))
    overflow_hidden = "hidden" in decl.get("overflow", "").lower()
    if re.search(r"rect\(\s*(0|1px)[\s,]+(0|1px)[\s,]+(0|1px)[\s,]+(0|1px)\s*\)|inset\(\s*50%|circle\(\s*0", clipv) or (
            tiny_box and overflow_hidden and pos in ("absolute", "fixed")):
        st.sr_only = st.sr_only or "screen_reader_only"
    for k in ("height", "max-height", "width", "max-width"):
        px = C.length_px(decl.get(k, "x"), st.font)
        if px is not None and px <= 0 and overflow_hidden:
            st.collapsed = st.collapsed or "zero_size_box"


def _classify(st: _State):
    if st.collapsed:
        return "collapsed", st.collapsed
    if st.visibility in ("hidden", "collapse"):
        return "collapsed", "visibility_hidden"
    if st.opacity <= 0.05:
        return "stealth", "transparent"
    if st.stealth:
        return "stealth", st.stealth
    if st.font <= 1.0:
        return "stealth", "zero_font"
    if st.color is not None and not st.clip_text:
        if st.color[3] <= 0.05:
            return "stealth", "transparent_color"
        bg = (255, 255, 255, 1.0) if st.bg == "default" else st.bg
        if st.bg == "default" and st.interactive:
            bg = "unknown"
        if bg != "unknown" and contrast([x / 255 for x in st.color[:3]], [x / 255 for x in bg[:3]]) < 1.15:
            return "stealth", "same_as_background"
    if st.sr_only:
        return "sr_only", st.sr_only
    return "visible", None


# --------------------------------------------------------------------------- main entry


def scan_html(raw: bytes | str, name: str = "<bytes>", *, base_url: str | None = None, fetch_resource=None,
              svg: bool = False, max_resources: int = 12) -> Report:
    html = raw if isinstance(raw, str) else _decode(raw)
    rep = Report(path=name, format="svg" if svg else "html", pages=1)
    root, comments = parse(html)
    page_host = urlparse(base_url).hostname if base_url else None

    # ---- stylesheets
    css_text = [node_text(n) for n in iter_nodes(root) if n.tag == "style"]
    fetched = 0
    script_srcs = []
    for n in iter_nodes(root):
        if n.tag == "link" and "stylesheet" in n.attrs.get("rel", "").lower() and n.attrs.get("href"):
            if fetch_resource and base_url and fetched < max_resources:
                data = fetch_resource(urljoin(base_url, n.attrs["href"]), "text/css")
                fetched += 1
                if data:
                    css_text.append(_decode(data))
        if n.tag == "script" and n.attrs.get("src"):
            script_srcs.append(n.attrs["src"])
    rules = C.RuleIndex(C.parse_stylesheet("\n".join(css_text)))

    # ---- walk
    buckets: dict[tuple, list[str]] = {}
    visible: list[str] = []
    side: list[tuple[str, str]] = []
    st0 = _State()
    stack = [(root, st0, False)]
    while stack:
        node, st, in_svg = stack.pop()
        if isinstance(node, str):
            cat, reason = _classify(st)
            if cat == "visible":
                visible.append(node)
            elif node.strip():
                buckets.setdefault((cat, reason), []).append(node)
            continue
        if node.tag == "#block":
            visible.append("\n")
            continue
        tag = node.tag
        if tag in ("script", "style", "noscript"):
            if tag == "script":
                if in_svg:
                    rep.findings.append(Finding(check="svg_script", severity="high",
                                                message="SVG contains a <script> (runs when the file is opened)"))
                _script_node(rep, node, side)
            elif tag == "noscript":
                side.append(("noscript", node_text(node)))
            continue
        if tag == "head":
            for c in iter_nodes(node):
                if c.tag == "title":
                    visible.append(node_text(c) + "\n")
                elif c.tag == "script":
                    _script_node(rep, c, side)
                elif c.tag == "meta":
                    _meta(rep, c, page_host, side)
                elif c.tag == "base" and c.attrs.get("href"):
                    h = urlparse(c.attrs["href"]).hostname
                    if h and page_host and h != page_host:
                        rep.findings.append(Finding(check="base_href", severity="low", text=c.attrs["href"],
                                                    message="<base> points relative links at another host"))
            continue
        child_svg = in_svg or tag == "svg"
        st = st.child()
        decl = rules.styles_for(node)
        if child_svg:
            decl = {**{SVG_PRES[k]: v for k, v in node.attrs.items() if k in SVG_PRES}, **decl}
        if node.attrs.get("style"):
            decl = {**decl, **C.parse_decls(node.attrs["style"])}
        _apply(st, node, decl, child_svg)
        _element_checks(rep, node, decl, st, page_host, side, child_svg)
        if tag == "meta":
            _meta(rep, node, page_host, side)
        for k in SIDE_ATTRS:
            if node.attrs.get(k):
                side.append((f"attribute.{k}", node.attrs[k]))
        block = tag in BLOCK
        if block:
            stack.append((Node("#block", [], None), st, child_svg))
        for c in reversed(node.children):
            stack.append((c, st, child_svg))
        if block:
            stack.append((Node("#block", [], None), st, child_svg))

    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(visible))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip() + "\n"
    rep.safe_pages = [text]
    rep.raw_pages = [text + "\n".join(t for v in buckets.values() for t in v)]

    # ---- hidden text
    for (cat, reason), texts in buckets.items():
        joined = " ".join(" ".join(t.split()) for t in texts)
        rep.findings += content_findings(joined, f"hidden text ({reason})", hidden=True)
        n_alnum = sum(c.isalnum() for c in joined)
        if cat == "stealth":
            rep.findings += hidden_text_finding(joined, "the page", reason, count=len(texts), fragment="low")
        elif cat == "sr_only" and n_alnum >= 300:
            rep.findings.append(Finding(check="hidden_text", severity="low", reason=reason, text=clip(joined),
                                        message="long screen-reader-only text"))
        elif cat == "collapsed" and n_alnum >= 1500:
            rep.findings.append(Finding(check="collapsed_text", severity="info", reason=reason, text=clip(joined),
                                        message=f"{n_alnum} characters of initially hidden content ({reason}); "
                                                "excluded from safe text"))

    for c in comments:
        if sum(ch.isalnum() for ch in c) >= 3 and not c.strip().startswith(("[if", "<![endif")):
            side.append(("html_comment", c))
    for ch, t in side:
        rep.findings += content_findings(t, ch, hidden=ch != "visible", side_channel=None)
    rep.findings += content_findings(text, "visible text", hidden=False)

    # ---- external scripts
    hosts = set()
    for src in script_srcs:
        u = urlparse(urljoin(base_url or "", src))
        if u.hostname:
            hosts.add(u.hostname)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", u.hostname or ""):
            rep.findings.append(Finding(check="suspicious_script", severity="medium", reason="ip_host", text=src,
                                        message="script loaded from a raw IP address"))
        rep.findings += js_findings(src, "script URL")
        if fetch_resource and base_url and fetched < max_resources and u.scheme in ("http", "https"):
            data = fetch_resource(u.geturl(), "script")
            fetched += 1
            if data:
                rep.findings += js_findings(_decode(data), f"external script {u.hostname}/…{u.path[-30:]}")
    if script_srcs or hosts:
        rep.findings.append(Finding(check="scripts", severity="info", message=f"{len(script_srcs)} external script(s) "
                                    f"from {len(hosts)} host(s): {', '.join(sorted(hosts)[:8])}"))
    return rep


def _decode(b: bytes) -> str:
    if b[:3] == b"\xef\xbb\xbf":
        return b[3:].decode("utf-8", "replace")
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    m = re.search(rb'charset=["\']?([\w-]+)', b[:2048])
    try:
        return b.decode(m.group(1).decode() if m else "utf-8")
    except (LookupError, UnicodeDecodeError):
        return b.decode("utf-8", "replace")


def _script_node(rep, node, side):
    typ = node.attrs.get("type", "").lower()
    code = node_text(node)
    if "json" in typ:
        side.append(("json_ld" if "ld+json" in typ else "script_json", code))
        return
    if typ and "javascript" not in typ and typ not in ("module", "text/babel"):
        side.append((f"script[{typ}]", code))
        return
    if code.strip():
        rep.findings += js_findings(code, "inline script")


def _meta(rep, node, page_host, side):
    a = node.attrs
    if a.get("http-equiv", "").lower() == "refresh":
        m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
        if m:
            tgt = m.group(1).strip()
            h = urlparse(tgt).hostname
            if tgt.lower().startswith(("javascript:", "data:")):
                rep.findings.append(Finding(check="meta_refresh", severity="high", text=tgt,
                                            message="meta refresh to a javascript:/data: URL"))
            elif h and h != page_host:
                rep.findings.append(Finding(check="meta_refresh", severity="medium", text=tgt,
                                            message="page auto-redirects to another host"))
    if a.get("content") and (a.get("name") or a.get("property")):
        side.append((f"meta.{a.get('name') or a.get('property')}", a["content"]))


def _element_checks(rep, node, decl, st, page_host, side, in_svg):
    a, tag = node.attrs, node.tag
    handlers = [k for k in a if k.startswith("on")]
    for k in handlers:
        rep.findings += js_findings(a[k], f"<{tag} {k}>")
    for k in ("href", "src", "action", "formaction", "xlink:href", "data"):
        v = a.get(k, "").strip()
        low = re.sub(r"[\s\x00-\x1f]", "", v).lower()
        if low.startswith("javascript:") and len(low) > len("javascript:") + 3 and low not in (
                "javascript:void(0)", "javascript:void(0);", "javascript:;"):
            js = js_findings(v, f"<{tag} {k}=javascript:>")
            rep.findings += js
            rep.findings.append(Finding(check="javascript_url", severity="high" if (in_svg or js) else "low",
                                        text=clip(v, 100), message=f"<{tag}> {k} runs JavaScript"))
        elif low.startswith(("data:text/html", "data:application/x-javascript", "data:text/javascript",
                             "data:image/svg+xml")) and tag not in ("img",):
            rep.findings.append(Finding(check="data_url", severity="high", text=clip(v, 80),
                                        message=f"<{tag}> {k} loads an inline HTML/script document"))
    if tag == "a" and "download" in a and EXEC_EXT.search(a.get("href", "") + " " + a.get("download", "")):
        rep.findings.append(Finding(check="executable_download", severity="high", text=a.get("href"),
                                    message="link downloads an executable file"))
    if tag in ("iframe", "frame"):
        w, h = C.length_px(a.get("width", "x")), C.length_px(a.get("height", "x"))
        dw = C.length_px(decl.get("width", "x"))
        dh = C.length_px(decl.get("height", "x"))
        tiny = any(x is not None and x <= 2 for x in (w, h, dw, dh))
        if tiny or st.collapsed or st.visibility == "hidden" or st.opacity <= 0.05:
            rep.findings.append(Finding(check="hidden_iframe", severity="high", text=a.get("src", "")[:120],
                                        message="invisible iframe (typical of drive-by downloads and click fraud)"))
        if a.get("srcdoc"):
            side.append(("iframe.srcdoc", re.sub(r"<[^>]+>", " ", a["srcdoc"])))
            rep.findings += js_findings(a["srcdoc"], "iframe srcdoc")
    if tag in ("object", "embed", "applet"):
        rep.findings.append(Finding(check="plugin_content", severity="medium", text=a.get("data") or a.get("src"),
                                    message=f"<{tag}> plugin content"))
    if in_svg and tag == "foreignobject":
        rep.findings.append(Finding(check="svg_foreign_object", severity="medium",
                                    message="SVG embeds HTML through <foreignObject>"))
    if in_svg and tag == "script":
        rep.findings.append(Finding(check="svg_script", severity="high", message="SVG contains a <script>"))
    if in_svg and handlers:
        rep.findings.append(Finding(check="svg_script", severity="high", text=", ".join(handlers),
                                    message="SVG element with event handlers (runs script when opened)"))
    if tag == "form":
        act = a.get("action", "")
        h = urlparse(act).hostname
        has_pw = any(isinstance(c, Node) and c.tag == "input" and c.attrs.get("type", "").lower() == "password"
                     for c in iter_nodes(node))
        if has_pw and h and h != page_host:
            rep.findings.append(Finding(check="credential_form", severity="high", text=act,
                                        message="password form submits to a different host (phishing pattern)"))
