# Deadband

**A real-time, passive OT network monitor — the Purdue Model as a live map,
with early warning when traffic starts to look like an attack.**

Deadband watches a copy of an industrial network's traffic, works out which
devices exist and who normally talks to whom, draws them on the Purdue Model
(Levels 5 → 0), and raises the alarm early — during an attacker's snooping
phase, before anything destructive happens. It is built for the plants that
can't afford enterprise OT security platforms: small utilities, water
systems, and factories.

> **Status: Phase 1 — simulated plant.** The app ships a built-in lab:
> five virtual devices (office PC, historian, HMI, two PLCs) generating
> real Modbus/TCP frames through the real pipeline — parser, SQLite
> store, live event log in the Events view. Detection lands phase by
> phase; see the architecture below.

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
