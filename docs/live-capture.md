# Live capture (Phase 7)

Deadband watches a real network interface with libpcap and feeds the
packets through the same pipeline as the simulation and the replays —
same parser, same rules layer, same anomaly layer, same analyst. The
only difference is where the packets come from.

## What you need

- **In the lab (this Mac):** pick your interface (usually `en0` for
  Wi-Fi, `en1`/similar for wired) and press Start. You will see your
  own traffic — your Mac talking to the router, the HMI polls if you
  run the lab — and the map will discover the real devices on your
  network. This is the fastest way to prove the detection layers work
  on real packets.
- **In a plant:** the sensor (a small PC running Deadband) plugs into
  a switch **mirror/SPAN port** or an inline **TAP**. You never touch
  the devices themselves. One sensor per switch area. Deadband is
  passive-only: it reads copies of traffic and never transmits.

## macOS permission (BPF)

macOS only lets privileged users open a network interface for capture.
If Start fails with a permission error, you have two options:

1. **Join the access_bpf group (recommended, one-time):**
   ```sh
   sudo dseditgroup -o edit -a $USER -t user access_bpf
   ```
   Log out and back in (or reboot) for the group to take effect.
   This is the same step Wireshark's installer does (its ChmodBPF
   package creates the group and the startup item).
2. **Run with sudo for a lab test:**
   ```sh
   sudo cargo tauri dev
   ```
   Fine for proving it works on your own Mac; don't make a habit of
   running the app as root.

## The blind check

A sensor that stops seeing traffic fails silently, and that is the
most dangerous failure a monitor can have. Deadband watches its own
capture continuously:

- **Flowing** — packets are arriving. Normal.
- **Gone quiet** — the capture was flowing, then nothing for over a
  minute. Deadband raises an alert ("Capture has gone quiet") that
  shows in the Events log, the bell and the latest-alert line. Check
  the mirror port / SPAN session first, then the cable.
- **Sees nothing** — the capture ran a full minute without a single
  packet. Usually the wrong interface, or the BPF permission above.

One alert per quiet episode: when traffic resumes, the latch clears,
so a *later* quiet spell alerts again instead of spamming the log.

## Drop counters

The status line shows packets seen and packets dropped. Drops are
shown, never hidden: if libpcap is dropping packets, the sensor is
overloaded (or the filter is too broad) and the numbers will say so.
On a quiet lab interface you should see zero drops.

## One feed at a time

Starting live capture stops the simulation and any replay, and
starting a replay or the simulation stops a live capture. The
detection layers are per-feed — each feed learns its own baseline
from the traffic it sees — so mixing feeds would poison the
baseline.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| No interfaces in the dropdown | libpcap can't see any interface; on macOS this usually means the BPF step above hasn't been done yet, or the app was launched oddly. |
| "Permission denied" on Start | BPF access — see above. |
| Capture runs but sees nothing | Wrong interface (pick the one with traffic), or the mirror port isn't mirroring yet. |
| "Capture has gone quiet" | The mirror/SPAN session stopped, the cable moved, or the segment genuinely went silent. Check the switch first. |
| Drops climbing | The interface is busier than the sensor keeps up with. On a lab Mac, close the heavy apps; on a plant sensor, use a smaller span or a faster box. |
