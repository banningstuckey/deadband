# Setting up the local AI (Ollama)

Deadband's analyst (the plain-English incident explanations) and the
plain-English log query both run on a language model on your own
machine, through [Ollama](https://ollama.com). Nothing is sent
anywhere: the model, the prompts, and your plant data all stay local.
Deadband works fully without it — the analyst and the AI query toggle
just stay quiet until a model is there.

## Why Ollama isn't bundled with Deadband

Ollama is a separate application, not a library Deadband can ship
inside itself:

- It's roughly 1 GB on its own, and every model is several more GB
  (`llama3` is ~4.7 GB). Bundling it would make every Deadband
  download enormous, and the model files change on their own schedule.
- It has its own installer per operating system (a macOS app, a
  Windows installer, a Linux install script) and its own update
  channel. The supported way to get it is from its maker.
- It runs as its own background service on port 11434. Deadband just
  talks to that port on localhost — it never manages the service.

So instead of bundling it, Deadband detects it and guides you to the
one-time install below. The Settings view has a "Local AI (Ollama)"
card with the same steps and a Recheck button.

## Install

1. Download and install Ollama from <https://ollama.com/download>
   (macOS, Windows, or Linux). On Linux the same page offers the
   one-line install:
   `curl -fsSL https://ollama.com/install.sh | sh`
2. Pull a model. Deadband is tuned for the small general model
   `llama3` (the one the analyst was built and tested against):
   `ollama pull llama3`
   A larger alternative is `ollama pull llama3.1:8b` (8 GB, slower,
   better prose). Pick one in Settings → Preferred analyst model;
   "First available" just takes whatever is installed.
3. Ollama starts itself on login. Open Deadband → Settings → Local
   AI → Recheck. It should report "Ollama is running" and list your
   model.

## Troubleshooting

- **"No local model detected"** — Ollama isn't running. On macOS
  and Windows, launch the Ollama app once (it then stays in the
  menu bar / tray). On Linux, `ollama serve` in a terminal.
- **"Ollama is running but has no models yet"** — run
  `ollama pull llama3`, then Recheck.
- **The analyst times out** — the first answer after a fresh pull
  can be slow while the model loads into memory. A smaller model, or
  more RAM, helps. The explain call gives the model 180 seconds.
- **Port 11434 in use** — something else is already serving there.
  Deadband only ever talks to localhost, so check what's listening
  (`lsof -i :11434` on macOS/Linux).

## What the model sees

Only what Deadband sends it, per request: for an explanation, a
digested incident (the alert, its factors, nearby events — never raw
packets); for a query translation, your question plus the device
roster (labels and IPs) and the query grammar. The model answers in
plain text; a translation is validated against the real query parser
before it runs, and the generated query is always shown next to the
results so you can see exactly what ran.
