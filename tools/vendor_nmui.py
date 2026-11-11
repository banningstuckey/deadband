#!/usr/bin/env python3
"""Regenerate Deadband's vendored nmui copy from an nmui checkout.

Usage: python3 tools/vendor_nmui.py /path/to/nmui

Copies the pinned foundation CSS and components verbatim, EXCEPT each
component's JS header: nmui loads its CSS with a CSS module import
(`import X from "./x.css" with { type: "css" }` into adoptedStyleSheets).
WebKit — the engine inside Tauri's macOS WKWebView and Linux WebKitGTK —
cannot parse that syntax and kills the whole module, so no component
registers. The generated copy drops those two statements; the app loads
the same CSS files with plain <link> tags instead (see ui/index.html).
Component logic is never touched. See ui/vendor/nmui/VENDORED.md.
"""
import re, shutil, sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "~/workspace/nmui").expanduser()
DST = Path(__file__).resolve().parent.parent / "ui" / "vendor" / "nmui"
CSS = ["tokens", "typography", "motion", "base"]
COMPONENTS = ["navigation", "button", "card", "badge", "divider", "tabs", "menu", "text-field"]
HEADER = re.compile(
    r'import \w+ from "\./[\w-]+\.css" with \{ type: "css" \};\n\n'
    r'if \(!document\.adoptedStyleSheets\.includes\(\w+\)\) \{\n'
    r'  document\.adoptedStyleSheets\.push\(\w+\);\n\}\n')
NOTE = ("/* GENERATED for Deadband from nmui — do not hand-edit.\n"
        "   The CSS-module import header of the original is removed:\n"
        "   WebKit (Tauri's macOS/Linux webview) cannot parse it.\n"
        "   This component's CSS is loaded by ui/index.html instead.\n"
        "   Regenerate with tools/vendor_nmui.py. */\n")

for name in CSS:
    shutil.copy(SRC / "css" / f"{name}.css", DST / "css" / f"{name}.css")
for comp in COMPONENTS:
    out = DST / "components" / comp
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy(SRC / "components" / comp / f"{comp}.css", out / f"{comp}.css")
    js = (SRC / "components" / comp / f"{comp}.js").read_text()
    js2, n = HEADER.subn("", js)
    assert n == 1, f"{comp}: CSS-import header not found — nmui format changed?"
    (out / f"{comp}.js").write_text(NOTE + js2)
    print(f"{comp}: copied, header stripped")
print("done")
