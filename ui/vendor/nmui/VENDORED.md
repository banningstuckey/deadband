# Vendored nmui — pinned copy

Deadband's UI library is [nmui](https://github.com/nativemui/nmui)
(Banning's own Material 3 vanilla web-component library). Per the UI
decision in `PROJECT_PLAN.md`, the app **pins** a specific nmui version
instead of tracking the moving repo: the files here are copied verbatim
from nmui and are not edited in place. To upgrade, re-copy from a newer
nmui release and bump the pin note below.

- **Pinned version:** nmui v0.40.0 (repo commit
  `6e2fc95d3d4b341ba7f7396272b0d1909ec9dd87`)
- **Vendored:** 2026-11-10
- **Scope:** shell and standard controls only. The Purdue map, risk
  timeline, and other data visualisations are custom SVG/canvas and
  never nmui.

## Files

Foundation CSS (`css/`): `tokens.css`, `typography.css`, `motion.css`,
`base.css` — plus `css/themes/deadband-industrial.css`, Deadband's own
theme file (generated from the nmui theming tool's Industrial Dark
preset; this file belongs to Deadband, not to nmui).

Components (`components/`, each an `x.js` + `x.css` pair, imported by
the app where used): `navigation`, `button`, `card`, `badge`, `divider`.

## Known gap — icon font

nmui's `<icon>` element renders Material Symbols ligatures; per nmui's
design the *app* loads the font. The demo loads it from Google Fonts,
but Deadband is local-first and must work on isolated plant networks,
so it does **not** fetch it. The rail currently uses text-only
destinations (the navigation component handles missing icons). Before
the Phase 2 shell ships, self-host the Material Symbols font file in
the app (a binary asset, added outside the text-only connector push)
and wire `@font-face` in `ui/app.css`.
