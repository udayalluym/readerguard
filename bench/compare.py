"""Compare readerguard with baseline scanners on the same attacked + clean files.

    .venv/bin/python -m bench.compare   -> bench/COMPARE.md, bench/out/compare.json, paper/tables/compare.tex

Each tool's output is mapped to two decisions:
  block  - readerguard safe:false | DocFirewall BLOCK | PhantomLint hidden suspicious phrase found
  flag   - block or warn          | FLAG or BLOCK    | (same as block)
Files a tool cannot open or does not support count as not detected (attacks) / not flagged (clean),
and are counted separately as 'unsupported'.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

OUT = Path("bench/out")
FMT = {"pdf": "PDF", "html": "HTML", "docx": "Word", "pptx": "PowerPoint", "xlsx": "Excel", "markdown": "Markdown",
       "image": "Image", "svg": "SVG"}
ORDER = ["pdf", "html", "docx", "pptx", "xlsx", "markdown", "svg", "image"]


def corpus():
    """file -> dict(format, kind, technique, payload, ig_block, ig_flag)"""
    m = {}
    p = json.loads((OUT / "results.json").read_text())
    for r in p["attacks"]:
        m[r["file"]] = dict(format="pdf", kind="attack", technique=r["technique"], payload=r["payload"],
                            ig_block=r["verdict"] == "fail", ig_flag=r["verdict"] != "pass")
    for k, rs in p["clean"].items():
        if "as released" not in k:
            for r in rs:
                m[r["file"]] = dict(format="pdf", kind="clean", ig_block=r["verdict"] == "fail", ig_flag=r["verdict"] != "pass")
    mu = json.loads((OUT / "multi_results.json").read_text())
    for r in mu["attacks"]:
        m[r["file"]] = dict(format=r["format"], kind="attack", technique=r["technique"], payload=r["payload"],
                            ig_block=not r["safe"], ig_flag=r["verdict"] in ("warn", "fail"))
    for r in mu["clean"]:
        m[r["file"]] = dict(format=r["format"], kind="clean", ig_block=not r["safe"], ig_flag=r["verdict"] in ("warn", "fail"))
    return m


def load_tools(m):
    tools = {"readerguard": {f: (v["ig_block"], v["ig_flag"], True) for f, v in m.items()}}
    for prof in ("balanced", "strict"):
        p = OUT / f"baseline_docfirewall_{prof}.jsonl"
        if p.exists():
            d = {}
            for l in p.open():
                r = json.loads(l)
                v = r["verdict"]
                d[r["file"]] = (v == "BLOCK", v in ("FLAG", "BLOCK"), v is not None)
            tools[f"DocFirewall ({prof})"] = d
            if prof == "strict":
                ig = tools["readerguard"]
                tools["readerguard (strict sample)"] = {f: ig[f] for f in d if f in ig}
    p = OUT / "baseline_phantomlint.jsonl"
    if p.exists():
        d = {}
        for l in p.open():
            r = json.loads(l)
            ok = r.get("supported", True) and r.get("error") is None
            d[r["file"]] = (bool(r.get("hidden")) and ok, bool(r.get("hidden")) and ok, ok)
        tools["PhantomLint"] = d
    return tools


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "--"


def main():
    m = corpus()
    tools = load_tools(m)
    hidden = {f: v for f, v in m.items() if v["kind"] == "attack" and v["technique"] != "visible_injection"}
    clean = {f: v for f, v in m.items() if v["kind"] == "clean"}
    S = {}
    for name, d in tools.items():
        s = {"formats": {}}
        for scope in ORDER + ["all"]:
            A = [f for f, v in hidden.items() if scope in ("all", v["format"]) and f in d]
            C = [f for f, v in clean.items() if scope in ("all", v["format"]) and f in d]
            get = lambda f, i: d.get(f, (False, False, False))[i]
            row = dict(n=len(A), block=sum(get(f, 0) for f in A), flag=sum(get(f, 1) for f in A),
                       unsup=sum(not get(f, 2) for f in A), nc=len(C), cblock=sum(get(f, 0) for f in C),
                       cflag=sum(get(f, 1) for f in C))
            for kind in ("instruction", "fact", "active"):
                K = [f for f in A if hidden[f]["payload"] == kind]
                row[kind] = (sum(get(f, 0) for f in K), len(K))
            s["formats"][scope] = row
        S[name] = s
    (OUT / "compare.json").write_text(json.dumps(S, indent=1))

    names = list(tools)
    L = ["# Baseline comparison", "", "Hidden-content attacks (visible-injection baseline excluded) and clean files. "
         "*Block* = readerguard `safe:false`, DocFirewall BLOCK, PhantomLint hidden phrase found. "
         "*Flag* = block or warn/FLAG.", ""]
    L += ["| format | n | " + " | ".join(f"{t} block / flag" for t in names) + " |", "|---|---|" + "---|" * len(names)]
    for scope in ORDER + ["all"]:
        r0 = S[names[0]]["formats"][scope]
        cells = [f"{pct(S[t]['formats'][scope]['block'], S[t]['formats'][scope]['n'])} / {pct(S[t]['formats'][scope]['flag'], S[t]['formats'][scope]['n'])}" for t in names]
        L.append(f"| {scope} | {r0['n']} | " + " | ".join(cells) + " |")
    L += ["", "Clean files (false alarms):", "", "| format | n | " + " | ".join(f"{t} block / flag" for t in names) + " |",
          "|---|---|" + "---|" * len(names)]
    for scope in ORDER + ["all"]:
        r0 = S[names[0]]["formats"][scope]
        cells = [f"{pct(S[t]['formats'][scope]['cblock'], S[t]['formats'][scope]['nc'])} / {pct(S[t]['formats'][scope]['cflag'], S[t]['formats'][scope]['nc'])}" for t in names]
        L.append(f"| {scope} | {r0['nc']} | " + " | ".join(cells) + " |")
    L += ["", "By payload (all formats, block rate):", ""]
    for t in names:
        a = S[t]["formats"]["all"]
        L.append(f"- {t}: instruction {pct(*a['instruction'])}, fact {pct(*a['fact'])}, active {pct(*a['active'])}; "
                 f"unsupported/errored attacked files {a['unsup']}")
    Path("bench/COMPARE.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))

    # LaTeX (paper): each tool's decision that maps to "reject" -- readerguard safe:false, DocFirewall FLAG-or-BLOCK
    # (it never BLOCKs here), PhantomLint hidden phrase -- on attacked files (Det.) and clean files (FA).
    T = Path("paper/tables")
    T.mkdir(parents=True, exist_ok=True)
    cols = [("readerguard", "block", "cblock", "\\sys"), ("DocFirewall (balanced)", "flag", "cflag", "DocFirewall"),
            ("DocFirewall (strict)", "flag", "cflag", "DocFirewall strict$^\\dagger$"),
            ("PhantomLint", "block", "cblock", "PhantomLint")]
    cols = [c for c in cols if c[0] in S]
    tl = ["\\begin{tabular}{lrr" + "rr" * len(cols) + "}", "\\toprule",
          " & & & " + " & ".join(f"\\multicolumn{{2}}{{c}}{{{c[3]}}}" for c in cols) + " \\\\",
          "".join(f"\\cmidrule(lr){{{4 + 2 * i}-{5 + 2 * i}}}" for i in range(len(cols))),
          "Format & Att. & Clean & " + " & ".join(["Det. & FA"] * len(cols)) + " \\\\", "\\midrule"]
    def row(lab, scope, n, nc):
        cells = []
        for name, a, c, _ in cols:
            r = S[name]["formats"][scope]
            cells += [pct(r[a], r["n"]), pct(r[c], r["nc"])]
        return f"{lab} & {n} & {nc} & " + " & ".join(x.replace("%", "\\%") for x in cells) + " \\\\"
    for scope in ORDER:
        r0 = S["readerguard"]["formats"][scope]
        tl.append(row(FMT[scope], scope, r0["n"], r0["nc"]))
    tl.append("\\midrule")
    r0 = S["readerguard"]["formats"]["all"]
    tl.append(row("\\textbf{All}", "all", r0["n"], r0["nc"]))
    tl += ["\\bottomrule", "\\end{tabular}"]
    (T / "compare.tex").write_text("\n".join(tl) + "\n")

    # numbers for the text
    pl = [json.loads(l) for l in (OUT / "baseline_phantomlint.jsonl").open()] if (OUT / "baseline_phantomlint.jsonl").exists() else []
    N = {}
    for fmt in ("pdf", "html"):
        sub = [r for r in pl if r["supported"] and m[r["file"]]["kind"] == "attack" and m[r["file"]]["format"] == fmt
               and m[r["file"]].get("payload") == "instruction" and m[r["file"]]["technique"] != "visible_injection"]
        N[f"pl{fmt}ins"] = pct(sum(r["hidden"] for r in sub), len(sub)).replace("%", "\\%")
    N["plcrash"] = sum(1 for r in pl if r.get("error"))
    b = S.get("DocFirewall (balanced)", {}).get("formats", {}).get("all")
    if b:
        N["dfflag"] = pct(b["flag"], b["n"]).replace("%", "\\%")
        N["dffa"] = pct(b["cflag"], b["nc"]).replace("%", "\\%")
    st = S.get("DocFirewall (strict)", {}).get("formats", {}).get("all")
    if st:
        N["dfstrictn"] = st["n"] + st["nc"]
    (T / "compare_numbers.tex").write_text("\n".join(f"\\newcommand{{\\C{k.capitalize()}}}{{{v}}}" for k, v in N.items()) + "\n")


if __name__ == "__main__":
    main()
