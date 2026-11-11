"""Office documents: OOXML (docx/docm, pptx/pptm, xlsx/xlsm), OpenDocument, RTF and legacy OLE (.doc/.xls/.ppt).

Active content: VBA macros, Excel 4.0 macro sheets and Auto_Open names, ActiveX, embedded OLE objects,
DDE fields and formulas, remote templates / frames / OLE links (template injection, NTLM leaks over UNC
paths, ms-msdt: "Follina"-style URIs).
Hidden text: Word hidden runs (w:vanish), white / 1-pt text, tracked deletions, hidden slides and shapes,
off-slide shapes, very-hidden sheets, ';;;' number formats, white fonts in cells.
Side channels: comments, speaker notes, document properties, custom XML.
Matching is by XML local name, so Transitional and Strict OOXML namespaces both work.
"""
from __future__ import annotations

import io
import re
import zipfile

from defusedxml import ElementTree as ET

from .. import textscan
from ..content import content_findings, hidden_text_finding, novel_prose
from ..findings import Finding, Report, clip
from ..pdf.visibility import contrast

MAX_ENTRIES = 10_000
MAX_TOTAL = 400_000_000
MAX_PART = 60_000_000
DANGEROUS_URI = re.compile(r"^(ms-msdt|search-ms|ms-officecmd|mhtml|ms-word|ms-excel|ms-powerpoint|its|mk):", re.I)
EXEC_NAME = re.compile(rb"[\w\- ]+\.(exe|scr|bat|cmd|ps1|vbs|js|jse|wsf|hta|dll|lnk|msi|jar|com|cpl)\b", re.I)


def ln(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def attr(el, name, default=None):
    for k, v in el.attrib.items():
        if ln(k) == name:
            return v
    return default


def kids(el, name):
    return [c for c in el if ln(c.tag) == name]


def first(el, name):
    for c in el.iter():
        if ln(c.tag) == name:
            return c
    return None


class Pkg:
    def __init__(self, raw: bytes, rep: Report):
        self.z = zipfile.ZipFile(io.BytesIO(raw))
        self.names = self.z.namelist()
        self.rep = rep
        infos = self.z.infolist()
        total = sum(i.file_size for i in infos)
        bomb = any(i.file_size > 50_000_000 and i.file_size > 200 * max(1, i.compress_size) for i in infos)
        if len(infos) > MAX_ENTRIES or total > MAX_TOTAL or bomb:
            raise ValueError("archive is a decompression bomb (entry count / expanded size / ratio over limits)")

    def read(self, name) -> bytes:
        info = self.z.getinfo(name)
        if info.file_size > MAX_PART:
            raise ValueError(f"part {name} too large")
        return self.z.read(name)

    def xml(self, name):
        if name not in self.names:
            return None
        try:
            return ET.fromstring(self.read(name))
        except Exception as e:
            self.rep.findings.append(Finding(check="malformed_xml", severity="low", reason=name,
                                             message=f"cannot parse {name}: {type(e).__name__}"))
            return None

    def rels(self, part):
        d, f = part.rsplit("/", 1) if "/" in part else ("", part)
        root = self.xml(f"{d}/_rels/{f}.rels" if d else f"_rels/{f}.rels")
        out = {}
        if root is not None:
            for r in root:
                out[attr(r, "Id")] = (attr(r, "Type", ""), attr(r, "Target", ""), attr(r, "TargetMode", ""))
        return out


def _resolve(base_part: str, target: str) -> str:
    if target.startswith("/"):
        return target[1:]
    parts = base_part.split("/")[:-1] + target.split("/")
    out = []
    for p in parts:
        if p == "..":
            if out:
                out.pop()
        elif p and p != ".":
            out.append(p)
    return "/".join(out)


def _all_text(el) -> str:
    return " ".join(t.text for t in el.iter() if ln(t.tag) in ("t", "delText", "instrText") and t.text) if el is not None else ""


# --------------------------------------------------------------------------- shared OOXML checks

def common_checks(pkg: Pkg, rep: Report, body_tokens: set) -> None:
    names, F = pkg.names, rep.findings
    ct = pkg.read("[Content_Types].xml").decode("utf-8", "ignore") if "[Content_Types].xml" in names else ""
    vba = [n for n in names if n.lower().endswith(("vbaproject.bin", "vbadata.xml"))]
    if vba or "macroEnabled" in ct or "vbaProject" in ct:
        F.append(Finding(check="macros", severity="high", text=", ".join(vba)[:120],
                         message="document contains VBA macros"))
    if any("/macrosheets/" in n.lower() or "/intlmacrosheets/" in n.lower() for n in names):
        F.append(Finding(check="macros", severity="critical", reason="excel4",
                         message="workbook contains Excel 4.0 (XLM) macro sheets"))
    if any("/activex/" in n.lower() for n in names):
        F.append(Finding(check="activex", severity="high", message="document contains ActiveX controls"))
    emb = [n for n in names if "/embeddings/" in n.lower()]
    if emb:
        exe = [m.group(0).decode("latin-1") for n in emb for m in [EXEC_NAME.search(pkg.read(n)[:5_000_000])] if m]
        if exe:
            F.append(Finding(check="embedded_executable", severity="critical", text=", ".join(exe)[:120],
                             message="embedded object packages an executable or script"))
        else:
            F.append(Finding(check="embedded_object", severity="medium", text=", ".join(emb)[:120],
                             message=f"{len(emb)} embedded OLE object(s) or package(s)"))

    ext_links = 0
    for n in names:
        if not n.endswith(".rels"):
            continue
        root = pkg.xml(n)
        if root is None:
            continue
        for r in root:
            typ, tgt, mode = attr(r, "Type", ""), attr(r, "Target", ""), attr(r, "TargetMode", "")
            kind = typ.rsplit("/", 1)[-1]
            if DANGEROUS_URI.match(tgt):
                F.append(Finding(check="dangerous_uri", severity="critical", text=tgt[:120],
                                 message=f"relationship uses a protocol handler that can run code ({kind})"))
                continue
            if mode != "External":
                continue
            unc = tgt.startswith(("\\\\", "file:", "smb:")) or re.match(r"^[a-z]+://\d+\.\d+\.\d+\.\d+", tgt, re.I)
            if kind in ("attachedTemplate", "oleObject", "frame", "subDocument", "control", "aFChunk", "package"):
                F.append(Finding(check="remote_content", severity="high", reason=kind, text=tgt[:120],
                                 message=f"loads a remote {kind} when opened (template / OLE injection)"))
            elif unc:
                F.append(Finding(check="remote_content", severity="high", reason="unc_path", text=tgt[:120],
                                 message="external link to a file share or raw IP (credential / NTLM leak)"))
            elif kind == "image":
                F.append(Finding(check="remote_content", severity="low", reason="remote_image", text=tgt[:120],
                                 message="remote image (tracking beacon when opened)"))
            elif kind == "externalLinkPath":
                F.append(Finding(check="external_link", severity="medium", text=tgt[:120],
                                 message="workbook links to an external workbook"))
            else:
                ext_links += 1
    if ext_links:
        F.append(Finding(check="hyperlinks", severity="info", message=f"{ext_links} external hyperlink(s)"))

    for part, fields in (("docProps/core.xml", ("title", "subject", "description", "keywords", "creator")),
                         ("docProps/app.xml", ("Company", "Manager")), ("docProps/custom.xml", None)):
        root = pkg.xml(part)
        if root is None:
            continue
        items = ([(ln(el.tag), (el.text or "").strip()) for el in root.iter() if ln(el.tag) in fields]
                 if fields else
                 [(f"custom.{attr(el, 'name', '?')}", " ".join(t.strip() for t in el.itertext()))
                  for el in root if ln(el.tag) == "property"])
        for name, txt in items:
            if not txt:
                continue
            ch = f"properties.{name}"
            F.extend(content_findings(txt, ch, hidden=True))
            F.extend(novel_prose(txt, body_tokens, ch))
    for n in names:
        if n.startswith("customXml/item") and n.endswith(".xml") and "Props" not in n:
            root = pkg.xml(n)
            txt = " ".join(t.strip() for t in (root.itertext() if root is not None else []) if t.strip())
            F.extend(content_findings(txt, "custom_xml", hidden=True, side_channel="low"))


# --------------------------------------------------------------------------- DOCX

def _rpr_flags(rpr) -> dict:
    f = {}
    if rpr is None:
        return f
    for c in rpr:
        name = ln(c.tag)
        v = attr(c, "val")
        if name in ("vanish", "specVanish") and v not in ("0", "false", "off"):
            f["vanish"] = True
        elif name == "color" and v and v.lower() != "auto":
            f["color"] = v
        elif name == "sz" and v and v.isdigit():
            f["sz"] = int(v)
        elif name in ("shd",) and attr(c, "fill") and attr(c, "fill").lower() != "auto":
            f["bg"] = attr(c, "fill")
        elif name == "highlight" and v and v != "none":
            f["bg"] = {"white": "FFFFFF", "black": "000000", "yellow": "FFFF00"}.get(v, "808080")
        elif name == "rStyle" and v:
            f["rStyle"] = v
    return f


def _hex(c):
    try:
        return tuple(int(c[i:i + 2], 16) / 255 for i in (0, 2, 4)) if c and len(c) >= 6 else None
    except ValueError:
        return None


def _run_reason(fl: dict, page_bg) -> str | None:
    if fl.get("vanish"):
        return "hidden_run"
    if fl.get("sz") is not None and fl["sz"] <= 2:
        return "tiny_font"
    col = _hex(fl.get("color", ""))
    bg = _hex(fl.get("bg", "")) or page_bg
    if col and contrast(col, bg) < 1.15:
        return "same_as_background"
    return None


def scan_docx(pkg: Pkg, rep: Report) -> None:
    styles, defaults = {}, {}
    sroot = pkg.xml("word/styles.xml")
    if sroot is not None:
        for st in sroot.iter():
            if ln(st.tag) == "style":
                fl = _rpr_flags(first(st, "rPr"))
                based = first(st, "basedOn")
                styles[attr(st, "styleId")] = (fl, attr(based, "val") if based is not None else None)
        dd = first(sroot, "rPrDefault")
        defaults = _rpr_flags(first(dd, "rPr")) if dd is not None else {}

    def style_flags(sid, depth=0):
        if not sid or sid not in styles or depth > 8:
            return {}
        fl, based = styles[sid]
        return {**style_flags(based, depth + 1), **fl}

    doc_main = "word/document.xml"
    parts = [doc_main] + sorted(n for n in pkg.names if re.match(r"word/(header|footer)\d*\.xml$", n)) + \
        [n for n in ("word/footnotes.xml", "word/endnotes.xml") if n in pkg.names]
    page_bg = (1.0, 1.0, 1.0)
    buckets: dict[str, list[str]] = {}
    visible_pages, fields = [], []
    for part in parts:
        root = pkg.xml(part)
        if root is None:
            continue
        if part == doc_main:
            bgel = first(root, "background")
            if bgel is not None and _hex(attr(bgel, "color", "")):
                page_bg = _hex(attr(bgel, "color"))
        parent = {c: p for p in root.iter() for c in p}
        lines = []
        for p in root.iter():
            if ln(p.tag) != "p":
                continue
            ppr = first(p, "pPr")
            pstyle = first(ppr, "pStyle") if ppr is not None else None
            pfl = {**defaults, **style_flags(attr(pstyle, "val") if pstyle is not None else None)}
            vis = []
            for r in p.iter():
                if ln(r.tag) != "r":
                    continue
                anc, deleted, own_p = parent.get(r), False, True
                while anc is not None and anc is not p:
                    if ln(anc.tag) in ("del", "moveFrom"):
                        deleted = True
                    if ln(anc.tag) == "p":
                        own_p = False
                        break
                    anc = parent.get(anc)
                if not own_p:
                    continue
                rfl = _rpr_flags(first(r, "rPr"))
                fl = {**pfl, **style_flags(rfl.get("rStyle")), **rfl}
                txt = ""
                for t in r:
                    k = ln(t.tag)
                    if k in ("t", "delText"):
                        txt += t.text or ""
                    elif k == "tab":
                        txt += "\t"
                    elif k in ("br", "cr"):
                        txt += "\n"
                    elif k == "instrText":
                        fields.append(t.text or "")
                if not txt:
                    continue
                reason = "tracked_deletion" if deleted else _run_reason(fl, page_bg)
                if reason:
                    buckets.setdefault(reason, []).append(txt)
                else:
                    vis.append(txt)
            for fs in p.iter():
                if ln(fs.tag) == "fldSimple" and attr(fs, "instr"):
                    fields.append(attr(fs, "instr"))
            if vis:
                lines.append("".join(vis))
        visible_pages.append("\n".join(lines))
        if any(ln(e.tag) == "altChunk" for e in root.iter()):
            rep.findings.append(Finding(check="alt_chunk", severity="medium",
                                        message="document imports an embedded HTML/RTF/MHT chunk (altChunk)"))
            for rid, (typ, tgt, mode) in pkg.rels(part).items():
                if typ.endswith("/aFChunk") and mode != "External":
                    target = _resolve(part, tgt)
                    if target in pkg.names:
                        from .html import scan_html
                        sub = scan_html(pkg.read(target), target)
                        rep.findings += [f for f in sub.findings if f.severity != "info"]

    rep.safe_pages = [p for p in visible_pages]
    rep.pages = len(rep.safe_pages)
    _field_checks(fields, rep)
    _report_buckets(rep, buckets, {"tracked_deletion": "low"})
    for part, ch in (("word/comments.xml", "comments"), ("word/commentsExtended.xml", "comments"),
                     ("word/glossary/document.xml", "glossary")):
        txt = _all_text(pkg.xml(part)) if part in pkg.names else ""
        rep.findings += content_findings(txt, ch, hidden=True, side_channel="low")
    settings = pkg.xml("word/settings.xml")
    if settings is not None:
        dv = " ".join(attr(e, "val", "") for e in settings.iter() if ln(e.tag) == "docVar")
        rep.findings += content_findings(dv, "document_variables", hidden=True, side_channel="low")


def _field_checks(fields, rep):
    for f in fields:
        s = " ".join(f.split())
        if re.search(r"\bDDE(AUTO)?\b", s, re.I):
            rep.findings.append(Finding(check="dde", severity="critical", text=clip(s, 120),
                                        message="DDE field: can launch a command when the document opens"))
        elif re.search(r"\b(INCLUDETEXT|INCLUDEPICTURE|IMPORT|LINK)\b.*(https?:|\\\\|file:)", s, re.I):
            rep.findings.append(Finding(check="remote_content", severity="high", reason="field", text=clip(s, 120),
                                        message="field pulls remote content when updated"))


def _report_buckets(rep, buckets, severity_override=None, collapsed=()):
    severity_override = severity_override or {}
    for reason, texts in buckets.items():
        joined = " ".join(" ".join(t.split()) for t in texts)
        rep.findings += content_findings(joined, f"hidden text ({reason})", hidden=True)
        if reason in collapsed:
            if sum(c.isalnum() for c in joined) >= 3:
                rep.findings.append(Finding(check="collapsed_text", severity="info", reason=reason, text=clip(joined),
                                            message=f"{len(texts)} hidden item(s) ({reason}); excluded from safe text"))
            continue
        fs = hidden_text_finding(joined, rep.format, reason, count=len(texts))
        if reason in severity_override:
            for f in fs:
                f.severity = severity_override[reason]
        rep.findings += fs
        rep.raw_pages.append(joined)


# --------------------------------------------------------------------------- PPTX

def _a_run_reason(rpr, shape_bg, slide_bg) -> str | None:
    if rpr is None:
        return None
    sz = attr(rpr, "sz")
    if sz and sz.isdigit() and int(sz) <= 150:
        return "tiny_font"
    for c in rpr:
        k = ln(c.tag)
        if k == "noFill":
            return "no_fill"
        if k == "solidFill":
            clr = first(c, "srgbClr")
            if clr is not None:
                alpha = first(clr, "alpha")
                if alpha is not None and int(attr(alpha, "val", "100000")) < 5000:
                    return "transparent"
                col = _hex(attr(clr, "val", ""))
                bg = shape_bg or slide_bg
                if col and bg and contrast(col, bg) < 1.15:
                    return "same_as_background"
    return None


def _solid(el):
    if el is None:
        return None
    sf = None
    for c in el:
        if ln(c.tag) == "solidFill":
            sf = c
    if sf is None:
        return None
    clr = first(sf, "srgbClr")
    return _hex(attr(clr, "val", "")) if clr is not None else None


def scan_pptx(pkg: Pkg, rep: Report) -> None:
    pres = pkg.xml("ppt/presentation.xml")
    sz = first(pres, "sldSz") if pres is not None else None
    W, H = (int(attr(sz, "cx", "9144000")), int(attr(sz, "cy", "6858000"))) if sz is not None else (9144000, 6858000)
    slides = sorted((n for n in pkg.names if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                    key=lambda n: int(re.search(r"(\d+)\.xml$", n).group(1)))
    buckets: dict[str, list[str]] = {}
    for sn in slides:
        root = pkg.xml(sn)
        if root is None:
            rep.safe_pages.append("")
            continue
        hidden_slide = attr(root, "show") == "0"
        bg = first(root, "bg")
        slide_bg = _solid(first(bg, "bgPr")) if bg is not None else None
        lines = []
        for sp in root.iter():
            if ln(sp.tag) not in ("sp", "graphicFrame"):
                continue
            nv = first(sp, "cNvPr")
            shape_hidden = nv is not None and attr(nv, "hidden") in ("1", "true")
            off, ext = first(sp, "off"), first(sp, "ext")
            off_slide = False
            if off is not None and ext is not None:
                try:
                    x, y = int(attr(off, "x", "0")), int(attr(off, "y", "0"))
                    cx, cy = int(attr(ext, "cx", "0")), int(attr(ext, "cy", "0"))
                    off_slide = x >= W or y >= H or x + cx <= 0 or y + cy <= 0
                except ValueError:
                    pass
            sppr = first(sp, "spPr")
            shape_bg = _solid(sppr)
            for p in sp.iter():
                if ln(p.tag) != "p":
                    continue
                vis = []
                for r in p:
                    if ln(r.tag) not in ("r", "fld"):
                        continue
                    t = first(r, "t")
                    txt = (t.text or "") if t is not None else ""
                    if not txt:
                        continue
                    reason = ("hidden_slide" if hidden_slide else "hidden_shape" if shape_hidden else
                              "off_slide" if off_slide else _a_run_reason(first(r, "rPr"), shape_bg, slide_bg))
                    if reason:
                        buckets.setdefault(reason, []).append(txt)
                    else:
                        vis.append(txt)
                if vis:
                    lines.append("".join(vis))
        rep.safe_pages.append("\n".join(lines))
    rep.pages = len(slides)
    _report_buckets(rep, buckets, {"hidden_slide": "medium"})
    notes = " ".join(_all_text(pkg.xml(n)) for n in pkg.names if re.match(r"ppt/notesSlides/notesSlide\d+\.xml$", n))
    rep.findings += content_findings(notes, "speaker_notes", hidden=True)
    if notes.strip():
        rep.findings.append(Finding(check="side_channel_text", severity="info", reason="speaker_notes",
                                    message="slides have speaker notes (many loaders index them)"))
    comments = " ".join(_all_text(pkg.xml(n)) for n in pkg.names if "/comments/" in n and n.endswith(".xml"))
    rep.findings += content_findings(comments, "comments", hidden=True, side_channel="low")


# --------------------------------------------------------------------------- XLSX

DANGER_FN = re.compile(r"\b(WEBSERVICE|CALL|REGISTER|EXEC|REGISTER\.ID|FOPEN|FWRITE|URLDOWNLOADTOFILE|SHELL)\s*\(", re.I)
DDE_FORMULA = re.compile(r"[A-Za-z0-9_]+\|'?[^'!]*'?!", re.I)


def scan_xlsx(pkg: Pkg, rep: Report) -> None:
    wb = pkg.xml("xl/workbook.xml")
    if wb is None:
        rep.error = "workbook.xml missing"
        return
    rels = pkg.rels("xl/workbook.xml")
    for dn in wb.iter():
        if ln(dn.tag) == "definedName" and re.match(r"^(_xlnm\.)?auto_(open|close)", attr(dn, "name", ""), re.I):
            rep.findings.append(Finding(check="macros", severity="critical", reason="auto_open",
                                        text=attr(dn, "name"), message="Auto_Open name runs macros on open"))
    shared = []
    ss = pkg.xml("xl/sharedStrings.xml")
    if ss is not None:
        for si in ss:
            if ln(si.tag) == "si":       # direct <t> or rich-text runs <r><t>; skip phonetic <rPh>
                parts = []
                for ch in si:
                    if ln(ch.tag) == "t":
                        parts.append(ch.text or "")
                    elif ln(ch.tag) == "r":
                        parts += [t.text or "" for t in ch if ln(t.tag) == "t"]
                shared.append("".join(parts))
    fonts, fills, xfs, hide_fmt = [], [], [], set()
    st = pkg.xml("xl/styles.xml")
    if st is not None:
        for nf in st.iter():
            if ln(nf.tag) == "numFmt" and re.fullmatch(r'\s*;\s*;\s*;\s*(@\s*)?', attr(nf, "formatCode", "") or ""):
                hide_fmt.add(attr(nf, "numFmtId"))
        fonts_el, fills_el, xfs_el = first(st, "fonts"), first(st, "fills"), first(st, "cellXfs")
        for f in (kids(fonts_el, "font") if fonts_el is not None else []):
            c, s = first(f, "color"), first(f, "sz")
            fonts.append((_hex((attr(c, "rgb", "") or "")[-6:]) if c is not None else None,
                          float(attr(s, "val", "11")) if s is not None else 11.0))
        for f in (kids(fills_el, "fill") if fills_el is not None else []):
            fg = first(f, "fgColor")
            pat = first(f, "patternFill")
            solid = pat is not None and attr(pat, "patternType") == "solid"
            fills.append(_hex((attr(fg, "rgb", "") or "")[-6:]) if (fg is not None and solid) else None)
        for x in (kids(xfs_el, "xf") if xfs_el is not None else []):
            xfs.append((int(attr(x, "fontId", "0")), int(attr(x, "fillId", "0")), attr(x, "numFmtId", "0")))

    buckets: dict[str, list[str]] = {}
    for sh in wb.iter():
        if ln(sh.tag) != "sheet":
            continue
        name, state = attr(sh, "name", "?"), attr(sh, "state", "visible")
        rid = attr(sh, "id")
        part = _resolve("xl/workbook.xml", rels.get(rid, ("", "", ""))[1]) if rid in rels else None
        root = pkg.xml(part) if part else None
        if root is None:
            continue
        hidden_cols = []
        for c in root.iter():
            if ln(c.tag) == "col" and attr(c, "hidden") in ("1", "true"):
                hidden_cols.append((int(attr(c, "min", "0")), int(attr(c, "max", "0"))))
        lines = [f"## {name}"]
        for row in root.iter():
            if ln(row.tag) != "row":
                continue
            row_hidden = attr(row, "hidden") in ("1", "true")
            cells = []
            for c in row:
                if ln(c.tag) != "c":
                    continue
                f = first(c, "f")
                if f is not None and f.text:
                    if DANGER_FN.search(f.text):
                        rep.findings.append(Finding(check="dangerous_formula", severity="high", text=clip(f.text, 100),
                                                    message=f"formula calls a network/system function ({name})"))
                    if DDE_FORMULA.search(f.text):
                        rep.findings.append(Finding(check="dde", severity="critical", text=clip(f.text, 100),
                                                    message=f"DDE formula can launch a command ({name})"))
                t = attr(c, "t", "n")
                v = first(c, "v")
                if t == "s" and v is not None and v.text and v.text.isdigit() and int(v.text) < len(shared):
                    val = shared[int(v.text)]
                elif t == "inlineStr":
                    val = "".join(x.text or "" for x in c.iter() if ln(x.tag) == "t")
                elif v is not None and v.text:
                    val = v.text
                else:
                    continue
                col = _col_index(attr(c, "r", ""))
                reason = None
                if state == "veryHidden":
                    reason = "very_hidden_sheet"
                elif state == "hidden":
                    reason = "hidden_sheet"
                elif row_hidden:
                    reason = "hidden_row"
                elif any(a <= col <= b for a, b in hidden_cols):
                    reason = "hidden_column"
                else:
                    s = int(attr(c, "s", "0"))
                    if s < len(xfs):
                        fid, flid, nfid = xfs[s]
                        if nfid in hide_fmt:
                            reason = "format_hides_value"
                        elif fid < len(fonts):
                            fcol, fsz = fonts[fid]
                            bg = fills[flid] if flid < len(fills) and fills[flid] else (1.0, 1.0, 1.0)
                            if fsz <= 1:
                                reason = "tiny_font"
                            elif fcol and contrast(fcol, bg) < 1.15:
                                reason = "same_as_background"
                if reason:
                    if t in ("s", "inlineStr", "str"):
                        buckets.setdefault(reason, []).append(val)
                else:
                    cells.append(val)
            if cells:
                lines.append("\t".join(cells))
        rep.safe_pages.append("\n".join(lines))
    rep.pages = len(rep.safe_pages)
    _report_buckets(rep, buckets, {"hidden_sheet": "medium"},
                    collapsed=("hidden_row", "hidden_column"))
    comments = " ".join(_all_text(pkg.xml(n)) for n in pkg.names
                        if re.match(r"xl/(comments\d*|threadedComments/.*)\.xml$", n))
    rep.findings += content_findings(comments, "cell_comments", hidden=True, side_channel="low")


def _col_index(ref: str) -> int:
    n = 0
    for ch in re.match(r"[A-Z]*", ref.upper()).group(0):
        n = n * 26 + ord(ch) - 64
    return n


# --------------------------------------------------------------------------- OpenDocument

def scan_odf(pkg: Pkg, rep: Report) -> None:
    if any(n.startswith(("Basic/", "Scripts/")) and not n.endswith("/") for n in pkg.names):
        rep.findings.append(Finding(check="macros", severity="high", message="OpenDocument file contains macros"))
    root = pkg.xml("content.xml")
    if root is None:
        rep.error = "content.xml missing"
        return
    vis, hidden = [], []
    for el in root.iter():
        k = ln(el.tag)
        if k in ("hidden-text", "hidden-paragraph"):
            hidden.append(attr(el, "string-value", "") or " ".join(el.itertext()))
        elif k in ("p", "h"):
            vis.append("".join(el.itertext()))
    rep.safe_pages = ["\n".join(vis)]
    rep.pages = 1
    _report_buckets(rep, {"hidden_text": hidden} if hidden else {})
    meta = pkg.xml("meta.xml")
    if meta is not None:
        rep.findings += content_findings(" ".join(meta.itertext()), "properties", hidden=True)
    txt = pkg.read("content.xml")[:MAX_PART]
    for m in re.finditer(rb'xlink:href="([^"]+)"', txt):
        u = m.group(1).decode("utf-8", "ignore")
        if DANGEROUS_URI.match(u) or u.startswith(("\\\\", "file:")):
            rep.findings.append(Finding(check="remote_content", severity="high", text=u[:120],
                                        message="link to a protocol handler or file share"))


# --------------------------------------------------------------------------- entry points

def scan_ooxml(raw: bytes, name: str, kind: str) -> Report:
    rep = Report(path=name, format=kind)
    try:
        pkg = Pkg(raw, rep)
    except (zipfile.BadZipFile, ValueError) as e:
        rep.error = str(e)
        rep.findings.append(Finding(check="malformed_archive", severity="high", message=str(e)))
        return rep
    try:
        {"docx": scan_docx, "pptx": scan_pptx, "xlsx": scan_xlsx, "odf": scan_odf}[kind](pkg, rep)
    except ValueError as e:
        rep.error = str(e)
    body = set(textscan.tokens(" ".join(rep.safe_pages)))
    if kind != "odf":
        common_checks(pkg, rep, body)
    visible = "\n\f".join(rep.safe_pages)
    rep.findings += content_findings(visible, "visible text", hidden=False)
    rep.raw_pages = rep.safe_pages + rep.raw_pages
    return rep


def scan_ole(raw: bytes, name: str) -> Report:
    """Legacy binary Office. Without an OLE parser we only look for macro streams and known exploit markers."""
    rep = Report(path=name, format="ole", pages=0)
    macro = b"_VBA_PROJECT" in raw or "VBA".encode("utf-16-le") in raw or b"Macros" in raw[:2_000_000]
    if macro:
        rep.findings.append(Finding(check="macros", severity="high", message="legacy Office file contains a VBA project"))
    if re.search(rb"Equation\.3|EQNEDT32", raw):
        rep.findings.append(Finding(check="exploit_marker", severity="high",
                                    message="Equation Editor object (CVE-2017-11882 vector)"))
    rep.findings.append(Finding(check="uninspectable", severity="medium",
                                message="legacy binary Office format: text and hidden content were not inspected; "
                                        "convert to .docx/.xlsx/.pptx for a full scan"))
    return rep


def scan_rtf(raw: bytes, name: str) -> Report:
    rep = Report(path=name, format="rtf", pages=1)
    s = raw[:MAX_PART].decode("latin-1", "ignore")
    if re.search(r"\\objupdate|\\objautlink", s):
        rep.findings.append(Finding(check="embedded_object", severity="high", reason="auto_update",
                                    message="RTF object set to update automatically (exploit pattern)"))
    elif re.search(r"\\object\b|\\objdata", s):
        rep.findings.append(Finding(check="embedded_object", severity="medium", message="RTF embeds an OLE object"))
    if re.search(r"Equation\.3|EQNEDT32", s, re.I):
        rep.findings.append(Finding(check="exploit_marker", severity="high",
                                    message="Equation Editor object (CVE-2017-11882 vector)"))
    m = re.search(r"\\\*\\template\s+([^}]+)", s)
    if m and re.search(r"https?:|\\\\\\\\", m.group(1)):
        rep.findings.append(Finding(check="remote_content", severity="high", reason="attachedTemplate",
                                    text=m.group(1)[:120], message="RTF loads a remote template"))
    hidden = " ".join(re.findall(r"\\v\s+([^\\{}]+)", s))
    body = re.sub(r"\{\\\*[^{}]*\}|\\'[0-9a-f]{2}|\\[a-z]+-?\d* ?|[{}]", " ", s)
    body = re.sub(r"\s+", " ", body)
    rep.safe_pages = [body.replace(hidden, "") if hidden else body]
    if hidden.strip():
        _report_buckets(rep, {"hidden_run": [hidden]})
    rep.findings += content_findings(rep.safe_pages[0], "visible text", hidden=False)
    return rep
