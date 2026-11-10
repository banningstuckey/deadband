# Deadband

**A real-time, passive OT network monitor — the Purdue Model as a live map,
with early warning when traffic starts to look like an attack.**

Deadband watches a copy of an industrial network's traffic, works out which
devices exist and who normally talks to whom, draws them on the Purdue Model
(Levels 5 → 0), and raises the alarm early — during an attacker's snooping
phase, before anything destructive happens. It is built for the plants that
can't afford enterprise OT security platforms: small utilities, water
systems, and factories.

> **Status: Phase 6 — optional AI analyst.** The app ships a
> built-in lab (five virtual devices generating real Modbus/TCP
> frames), the live Purdue map, PCAP replay with passive discovery,
> and three detection layers: seven hard rules evaluated per packet;
> a statistical early-warning layer that learns a baseline of normal
> and scores traffic in 30-second chunks with contributing factors;
> and an optional analyst that hands a *local* model (Ollama, same
> machine — nothing leaves it) a digested incident and returns a
> plain-English brief: what happened, what it resembles, what to
> check next. The analyst is advisory prose, clearly labelled
> AI-generated, and the app is complete without it. Live capture on
> a real interface is the remaining v1 phase.

## Try it in five minutes (the demo)

Deadband ships with a built-in simulated plant, so the whole demo
runs offline on one machine:

1. **Launch the app.** The splash fades into the Live map: seven
   Purdue bands, the dashed IT/OT DMZ in the middle.
2. **Start the plant** (Events view → *Start simulation*). Five
   devices appear on their levels — Office PC, Historian, HMI, two
   PLCs — and conduits pulse as Modbus traffic flows. Click any
   device for its recent activity.
3. **Let it learn.** Open the Rules view. Layer 1 (rules) is armed
   immediately; layer 2 (anomaly) flips from LEARNING to ARMED after
   a few minutes of traffic. Normal operation raises **zero** alerts
   — the test suite proves this, and you can watch it stay quiet.
4. **Fire the rogue laptop** (Rules → *Rogue laptop writes to a
   PLC*). Red alerts land in the Events log and flash on the map:
   new device, write from a non-HMI, write outside the pattern.
5. **Fire slow recon** (Rules → *Slow recon*). Nothing is written,
   nothing breaks — an unknown device just probes, quietly. The
   rules only note a new device; the **anomaly layer raises the
   early warning**, with its contributing factors listed. That gap —
   warning during reconnaissance, before anything destructive — is
   the point of the product.
6. **Replay a capture** (Events → *Replay the bundled sample*). A
   foreign plant Deadband has never seen is discovered passively
   into the UNPLACED strip — including its own rogue laptop, which
   the rules flag on sight.

## Releases

Pushing a `v*` tag builds macOS, Windows, and Linux installers via
GitHub Actions and drafts a GitHub Release with them attached.
Builds are **unsigned in v1**: macOS may require right-click → Open
the first time, and Windows SmartScreen may require *More info →
Run anyway*. Every push also runs the core test suite on all three
OSes.

The workflow ships as `docs/build.workflow.yml.txt` (GitHub Apps
can't create workflow files); activate it once with:

```
mkdir -p .github/workflows
cp docs/build.workflow.yml.txt .github/workflows/build.yml
git add .github/workflows/build.yml
git commit -m "CI workflow" && git push
```

## Brand assets

The Deadband logo (shield mark + wordmark) appears on the app's splash
screen from `ui/assets/deadband-logo.jpg`; the app icons in
`src-tauri/icons/` are the shield mark cropped from the same artwork.
These are binary files, so they travel outside the text-only sync —
if they are missing, the app still runs (the splash skips itself).

## Safety rules (non-negotiable)

These are design constraints, not settings:

1. **Passive only, forever.** Deadband reads copies of network traffic. It
   never scans, pings, probes, or transmits into a monitored network —
   active scanning can crash fragile industrial controllers and cause real
   outages.
2. **AI warns, AI never acts.** Detection layers raise warnings and explain
   them in plain English. Deadband never automatically blocks, disconnects,
   or reconfigures anything. A human decides.
3. **Local first, no cloud.** Plant data never leaves the user's machine.
   AI features, when present, run against a local model.
4. **Lab-proven first.** Development and testing happen against a built-in
   simulated plant and replayed packet captures — not on live critical
   infrastructure.

## How it works

```text
traffic source ─► parser ─► events ─► SQLite store ─► detection ─► live map
(simulated lab,    (IP +      │                          │  rules
 PCAP replay,      Modbus)    └─► asset inventory        │  anomaly (baseline)
 live mirror)                     (devices, Purdue       │  analyst (local LLM,
                                  levels, connections)   ▼  optional)
                                                       alerts
```

Detection is three layers: hard rules for known-bad patterns, a statistical
baseline that scores chunks of traffic for early warning ("something
appears wrong", with the reasons shown), and an optional local-LLM analyst
that turns flagged chunks into a plain-English incident summary.

## Stack

- **Rust** engine as a standalone library crate (`crates/deadband-core`) —
  source / parse / model / detect / store modules matching the pipeline.
- **Tauri 2** desktop shell (`src-tauri`) for Mac, Windows, and Linux from
  one codebase.
- **SQLite** (via rusqlite, bundled) for the asset inventory and event log.
- **Vanilla HTML/CSS/JS** frontend (`ui/`), with [nmui](https://nativemui.com)
  as the official UI component library — vendored and pinned at v0.40.0
  under `ui/vendor/nmui/` (see its `VENDORED.md`), themed by the single
  `deadband-industrial.css` theme file. nmui covers the shell and
  standard controls; the live Purdue map itself is hand-built SVG.

## Building (Mac)

Prerequisites: Xcode Command Line Tools and Rust via rustup — the short
checklist is in [MAC_SETUP.md](MAC_SETUP.md). Then:

```sh
cargo install tauri-cli --version "^2"   # once
cargo tauri dev                          # run the app in dev mode
```

The **first build is slow** (Tauri compiles its whole dependency tree,
several minutes) and creates a `target/` folder of a few GB. Later builds
are fast. `cargo clean` reclaims the space.

Run the engine's tests without the app:

```sh
cargo test -p deadband-core
```

## Authorship

Designed and maintained by Banning Stuckey; developed with AI
pair-programming assistance. All code reviewed, tested, and owned by the
maintainer.

## License

MIT — see [LICENSE](LICENSE).
