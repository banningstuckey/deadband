# Canary PLC

A fake Modbus/TCP controller that nothing legitimate ever talks to.
It is not in the real plant's inventory, no HMI polls it, no
historian reads it — so any connection to it, any request at all, is
an intruder by definition. No baseline, no false positives, no
threshold to tune. The touch *is* the alert.

## What it does

- Listens on a TCP port (default 502, the real Modbus port) and
  answers Modbus requests with plausible fake values: reads return
  deterministic registers that drift slowly, writes are echoed back,
  unknown functions get a Modbus exception.
- Every connection and every request is recorded as a Critical
  alert event in the store, streamed live to the event log, and the
  visitor joins the inventory as an unknown device (they show on the
  map's UNPLACED strip).
- The canary joins the inventory itself as a PLC at Level 1, labelled
  "Canary PLC (decoy)".

## The passive-only boundary

The monitor itself is passive-only, forever — it reads copies of
traffic and never transmits. The canary is the deliberate, opt-in
exception, and it is a *decoy*, not the monitor: it is off by
default, you start it by hand, it answers only requests addressed to
itself, and it never talks to a real device. A silent decoy teaches
nothing — an attacker who connects and gets nothing back leaves. So
the canary answers, plausibly, and records everything the visitor
does. The twin (feature program, last item) reuses this responder.

Canary traffic never trains the anomaly baseline: touches bypass
`process_packet_full` on purpose. The visitor is not normal,
whatever they do.

## Running it

The canary is **not** a feed — it runs alongside the simulation, a
replay, or live capture. Canary + live capture together is the ideal
combo: the capture sees the visitor's packets on the wire, the
canary logs the Modbus conversation.

- **Port 502** needs admin rights (ports below 1024 do). If starting
  on 502 fails with a permission error, run with `sudo` for a lab
  test, or use **port 1502** instead.
- **Listen on** defaults to `0.0.0.0` (every interface), so anything
  on the network can reach it. A decoy only on loopback catches
  nobody — but loopback (`127.0.0.1`) is the right choice for a
  first local test.
- macOS may ask to allow incoming network connections the first
  time the canary starts. Allow it — that is the canary listening,
  not the monitor phoning home.

## Testing it (lab)

From another terminal on the same machine, while the canary runs on
port 1502:

```python
python3 -c "
import socket, struct
s = socket.create_connection(('127.0.0.1', 1502))
# MBAP header + read holding registers, addr 0, 10 regs
s.sendall(struct.pack('>HHHBBHH', 0x42, 0, 6, 1, 3, 0, 10))
print(s.recv(256).hex())
"
```

You should get a Modbus response back — and the Events log should
immediately show "Canary PLC touched — 127.0.0.1 read holding
registers". A bare `nc 127.0.0.1 1502` connect (no request) also
counts as a touch.

## How it is built

- `crates/deadband-core/src/canary.rs` — the pure Modbus responder
  (`respond`, testable without a network), the `CanaryServer` (one
  thread per connection, touches via callback), and the alert-event
  builder. 8 tests, including a real TCP round-trip on an ephemeral
  port.
- `src-tauri/src/lib.rs` — `start_canary` / `stop_canary` /
  `canary_status` commands; the touch handler records the alert,
  upserts the visitor as an unknown device, and emits the event live.
- `ui/index.html` — the Canary PLC card in the Events view, polled
  every 5 s with the overview.
