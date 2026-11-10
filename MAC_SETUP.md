# Mac setup — Deadband

One-time setup on Banning's Mac, then the normal pull → build → play loop.
Everything here is free.

## 1. Xcode Command Line Tools

Tauri's build needs Apple's compiler toolchain:

```sh
xcode-select --install
```

(Click through the dialog; ~a few minutes. Skip if `cc --version` already
works in Terminal.)

## 2. Rust via rustup

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Accept the defaults, then open a fresh Terminal (or `source "$HOME/.cargo/env"`)
so `cargo` is on the PATH. Check:

```sh
cargo --version
rustc --version
```

## 3. Tauri CLI

```sh
cargo install tauri-cli --version "^2"
```

This compiles the CLI from source — also slow the first time (several
minutes). It only happens once.

## 4. Get the code

Either clone the repo (once it exists):

```sh
git clone https://github.com/banningstuckey/deadband.git
cd deadband
```

…or unzip a source delivery into a folder and `cd` into it.

After that, updates are just:

```sh
git pull
```

## 5. First run

```sh
cargo tauri dev
```

**What to expect:**

- The first build compiles the entire Tauri + SQLite dependency tree —
  expect several minutes and a `target/` folder of a few GB. This is
  normal and happens once; later builds take seconds.
- A window titled **Deadband** should open: dark page, "Phase 0 —
  skeleton", an engine-status line served by the Rust core, and the
  Purdue levels listed as a static placeholder.
- If the engine-status line shows an error instead of "Deadband core
  v0.1.0", copy the whole Terminal output and send it back — that's the
  bug report we need.

## 6. Handy commands

```sh
cargo test -p deadband-core   # run the engine's unit tests (no window)
cargo check --workspace       # fast compile check of everything
cargo clean                   # delete target/ and reclaim several GB
```

## Troubleshooting

- **`cargo: command not found`** — open a new Terminal, or run
  `source "$HOME/.cargo/env"`.
- **Build complains about missing Apple SDKs** — re-run step 1.
- **Gatekeeper grumbles about an unsigned build later on** — expected
  until/unless the project gets an Apple Developer account ($99/yr);
  dev builds via `cargo tauri dev` are unaffected.
