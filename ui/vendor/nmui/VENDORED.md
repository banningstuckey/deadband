# Vendored nmui — pinned copy

Deadband's UI library is [nmui](https://github.com/nativemui/nmui)
(Banning's own Material 3 vanilla web-component library). Per the UI
decision in `PROJECT_PLAN.md`, the app **pins** a specific nmui version
instead of tracking the moving repo: the files here are generated from
nmui by `tools/vendor_nmui.py` and are not hand-edited. To upgrade,
re-run that script against a newer nmui checkout and bump the pin note
below.

**One deliberate deviation from verbatim:** each component's JS is
missing its first two statements — the CSS module import
(`import X from "./x.css" with { type: "css" }`) and the
`adoptedStyleSheets` push. WebKit, the engine inside Tauri's macOS
WKWebView (and Linux's WebKitGTK), cannot parse CSS module imports and
kills the whole module, so no component registers (confirmed on a real
Mac build 2026-11-10: theme CSS loaded, components never upgraded).
The generator strips only that header; component logic is untouched,
and the app loads the same CSS files with plain `<link>` tags in
`ui/index.html`. Upstream nmui keeps its CSS-import design — this is
an app-side adaptation for the desktop webview, not an nmui change.

- **Pinned version:** nmui v0.43.3 (local checkout, `app.js` version;
  the checkout carries no git history, so no repo commit to record)
- **Vendored:** 2026-11-10 (v0.40.0) · re-vendored 2026-11-11 (v0.43.0,
  v0.43.1, then v0.43.3 the same day): against the v0.40.0 pin the
  shell components diffed byte-identical at v0.43.0, so that bump
  only added menu + text-field for the Settings exposed-dropdown
  fields; v0.43.1 brought the navigation rail-group legibility fix;
  v0.43.3 added collapsed-rail hover-expand + group-parent tiles
  (Play Console pattern), v0.43.4 REVERTED the hover-expand (groups
  open by click only — the screenshots were only about grouping),
  and v0.43.5 wraps an open group in one tinted container in the
  expanded rail; v0.43.6 widens the expanded rail to 360dp, hides
  the destinations scrollbar, and renders nested groups as plain
  surface blocks; v0.43.7 makes an open nested group one seamless
  block (parent as the block's top half, no gap line). Deadband's
  rail is expanded and has no groups, so all six navigation changes
  are behavior-neutral here — the pin stays current because Banning
  tracks nmui closely.
- **Scope:** shell and standard controls only. The Purdue map, risk
  timeline, and other data visualisations are custom SVG/canvas and
  never nmui.

## Files

Foundation CSS (`css/`): `tokens.css`, `typography.css`, `motion.css`,
`base.css` — plus `css/themes/deadband-industrial.css`, Deadband's own
theme file (generated from the nmui theming tool's Industrial Dark
preset; this file belongs to Deadband, not to nmui).

Components (`components/`, each an `x.js` + `x.css` pair, imported by
the app where used): `navigation`, `button`, `card`, `badge`, `divider`,
`tabs`, `menu`, `text-field`.

## Known gap — icon font

nmui's `<icon>` element renders Material Symbols ligatures; per nmui's
design the *app* loads the font. The demo loads it from Google Fonts,
but Deadband is local-first and must work on isolated plant networks,
so it does **not** fetch it. The rail currently uses text-only
destinations (the navigation component handles missing icons). Before
the Phase 2 shell ships, self-host the Material Symbols font file in
the app (a binary asset, added outside the text-only connector push)
and wire `@font-face` in `ui/app.css`.
