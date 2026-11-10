//! Detection: three layers that turn events into alerts.
//!
//! **Safety rule: detection outputs opinions, never actions.** Layers
//! return [`Alert`]s for a human to judge. Nothing in this module can
//! block traffic, disconnect a device, or change any configuration —
//! by design, there is no code path here that could.
//!
//! Layers, in evaluation order:
//!
//! 1. [`RulesLayer`] — hard rules for known-bad patterns (Phase 4).
//!    Instant, deterministic, every alert cites its receipts.
//! 2. [`AnomalyLayer`] — statistical early warning (Phase 5). Learns a
//!    baseline of normal, aggregates traffic into time-window chunks,
//!    and scores each chunk against it, always explaining *why* the
//!    score moved. This layer's job is to fire during an attacker's
//!    reconnaissance — before anything destructive happens.
//! 3. [`AnalystLayer`] — optional local LLM (Phase 6). Reads chunk
//!    summaries and flagged anomalies and writes a plain-English
//!    incident narrative. Advisory prose only; the app works 100%
//!    without it.

use crate::model::{DeviceRole, Event, EventKind, PurdueLevel};
use std::net::IpAddr;

/// How urgently a human should look at an [`Alert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational — worth recording, not worth waking anyone.
    Info,
    /// Low concern.
    Low,
    /// Worth investigating today.
    Medium,
    /// Investigate now.
    High,
    /// Something is very likely attacking the process right now.
    Critical,
}

/// One detection finding, written for a human: what fired, why, and the
/// receipts (contributing factors / triggering events) behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    /// When the alert was raised, Unix seconds.
    pub timestamp: i64,
    /// Which layer raised it ("rules", "anomaly", "analyst").
    pub layer: &'static str,
    /// How urgent it is.
    pub severity: Severity,
    /// One-line headline ("Office PC talked directly to a PLC").
    pub title: String,
    /// Plain-English explanation of why this matters.
    pub detail: String,
    /// The device the alert is about, when singular.
    pub device_ip: Option<IpAddr>,
    /// Explainable factors behind the alert, each with its weight —
    /// e.g. ("new peer", 40). Anomaly alerts are meaningless without
    /// these; rules alerts list the triggering facts instead.
    pub factors: Vec<(String, i32)>,
}

/// A detection layer. Layers are evaluated in order over the same event
/// stream; each keeps whatever internal state it needs (rule tables,
/// baselines, …) and returns zero or more alerts.
pub trait DetectionLayer {
    /// Layer identifier used in [`Alert::layer`].
    fn name(&self) -> &'static str;

    /// Evaluates a batch of events (typically one time-window chunk)
    /// and returns any alerts raised.
    fn evaluate(&mut self, events: &[Event]) -> Vec<Alert>;
}

/// Layer 1 — hard rules (Phase 4). The initial rule set:
///
/// 1. new device appears · 2. IT-level device talks directly to a Level 1
/// controller · 3. controller receives a write from a non-HMI source ·
/// 4. traffic crosses a never-before-crossed level boundary · 5.
/// destination matches a threat-intel list · 6. device traffic rate
/// ≳100× normal · 7. Modbus write outside the normal command pattern.
///
/// Rules evaluate *packets*, not event chunks (the trait below serves
/// the chunk-based layers), so this layer's real entry point is
/// [`RulesLayer::observe_packet`], called by the engine per packet.
///
/// **Baseline.** Pattern rules (4, 6, 7) need to know what normal
/// looks like before they may shout. A layer learns a baseline two
/// ways: reconstructed from the store's history at construction
/// (connections → level pairs, stored write events → writer pairs,
/// ≥300 stored events → baseline already exists), and live, during
/// its first [`BASELINE_PACKETS`] packets. Pair/write rules stay
/// silent — recording, not alerting — until the baseline seals.
/// Absolute rules (1, 2, 3, 5) have no legitimate form and fire from
/// the first packet. Dedup is per session: each distinct violation
/// alerts once per rules-layer lifetime.
#[derive(Debug)]
pub struct RulesLayer {
    /// Ordered level pairs traffic has legitimately used.
    baseline_pairs: std::collections::HashSet<(PurdueLevel, PurdueLevel)>,
    /// (writer, target) pairs that legitimately write.
    write_pairs: std::collections::HashSet<(IpAddr, IpAddr)>,
    /// Dedup keys of alerts already fired this session.
    fired: std::collections::HashSet<String>,
    /// Per-source packet timestamps (seconds) inside the rate window.
    windows: std::collections::HashMap<IpAddr, std::collections::VecDeque<i64>>,
    /// Largest rate window each source showed during baseline.
    baseline_window_max: std::collections::HashMap<IpAddr, usize>,
    /// Packets this layer has observed.
    packets_seen: usize,
    /// True when the store already held a baseline at construction.
    sealed_from_history: bool,
    /// Bundled threat-intel addresses (documentation TEST-NET ranges
    /// stand in for a real feed in v1; file import is a later phase).
    intel: Vec<IpAddr>,
}

/// Packets of live observation that complete a baseline when the
/// store held no history.
pub const BASELINE_PACKETS: usize = 150;
/// Stored events at/above which history counts as a sealed baseline.
pub const BASELINE_EVENTS: i64 = 300;
/// Rate window, seconds.
const RATE_WINDOW_S: i64 = 10;
/// Floor for the rate rule: fewer packets than this in a window is
/// never a spike, whatever the multiplier says.
const RATE_FLOOR: usize = 60;

/// Static description of one rule, for the Rules view.
#[derive(Debug, Clone, Copy)]
pub struct RuleInfo {
    /// Stable rule id ("write-from-non-hmi").
    pub id: &'static str,
    /// Human name.
    pub name: &'static str,
    /// One-line description of what it watches.
    pub description: &'static str,
}

/// The seven rules, in evaluation order.
pub fn rule_catalog() -> Vec<RuleInfo> {
    vec![
        RuleInfo { id: "new-device", name: "New device", description: "A device never seen before appears on the network." },
        RuleInfo { id: "it-to-controller", name: "IT talks to a controller", description: "A Level 4/5 (IT) device talks directly to a Level 1 controller, bypassing the DMZ." },
        RuleInfo { id: "write-from-non-hmi", name: "Write from a non-HMI", description: "A controller receives a write/control command from something that is not its HMI or engineering station." },
        RuleInfo { id: "new-level-crossing", name: "New level crossing", description: "Traffic crosses a Purdue level boundary it has never crossed before (after baseline)." },
        RuleInfo { id: "threat-intel", name: "Threat-intel match", description: "Traffic to or from an address on the threat-intel list." },
        RuleInfo { id: "rate-spike", name: "Traffic rate spike", description: "A device sends ~100× its normal traffic rate (floored at 60 packets per 10 s)." },
        RuleInfo { id: "write-outside-pattern", name: "Write outside the pattern", description: "A device writes to a controller it has never written to before (after baseline)." },
    ]
}

/// Bundled demo intel: TEST-NET documentation addresses (192.0.2.0/24,
/// 198.51.100.0/24, 203.0.113.0/24 are reserved and never real), used
/// so the rule is testable without shipping real-world bad IPs in v1.
fn bundled_intel() -> Vec<IpAddr> {
    vec![
        "203.0.113.66".parse().expect("literal"),
        "198.51.100.23".parse().expect("literal"),
    ]
}

impl Default for RulesLayer {
    fn default() -> RulesLayer {
        RulesLayer::new()
    }
}

impl RulesLayer {
    /// A rules layer with an empty baseline (unit tests, first runs).
    pub fn new() -> RulesLayer {
        RulesLayer {
            baseline_pairs: Default::default(),
            write_pairs: Default::default(),
            fired: Default::default(),
            windows: Default::default(),
            baseline_window_max: Default::default(),
            packets_seen: 0,
            sealed_from_history: false,
            intel: bundled_intel(),
        }
    }

    /// A rules layer whose baseline is reconstructed from everything
    /// the store already knows — how the app starts it, so a restarted
    /// monitor does not re-learn (or re-alert) from zero.
    pub fn from_store(store: &crate::store::Store) -> RulesLayer {
        let mut layer = RulesLayer::new();
        if let (Ok(devices), Ok(connections)) = (store.list_devices(), store.list_connections()) {
            let level_of: std::collections::HashMap<IpAddr, PurdueLevel> = devices
                .iter()
                .filter_map(|d| d.level.map(|level| (d.ip, level)))
                .collect();
            for conn in &connections {
                if let (Some(a), Some(b)) = (level_of.get(&conn.src_ip), level_of.get(&conn.dst_ip)) {
                    if a != b {
                        layer.baseline_pairs.insert((*a, *b));
                        layer.baseline_pairs.insert((*b, *a));
                    }
                }
            }
        }
        if let Ok(pairs) = store.write_pairs() {
            layer.write_pairs.extend(pairs);
        }
        layer.sealed_from_history = store.event_count().unwrap_or(0) >= BASELINE_EVENTS;
        layer
    }

    /// Whether the pattern rules have a sealed baseline and may fire.
    pub fn baseline_sealed(&self) -> bool {
        self.sealed_from_history || self.packets_seen > BASELINE_PACKETS
    }

    fn fire(&mut self, key: String, alert: Alert, out: &mut Vec<Alert>) {
        if self.fired.insert(key) {
            out.push(alert);
        }
    }

    /// Evaluates one packet (already processed by the pipeline — the
    /// events it produced are passed so discovery is visible) and
    /// returns any alerts raised.
    pub fn observe_packet(
        &mut self,
        store: &crate::store::Store,
        packet: &crate::source::Packet,
        packet_events: &[Event],
    ) -> Vec<Alert> {
        let parsed = match crate::parse::parse_packet(packet) {
            Ok(parsed) => parsed,
            Err(_) => return Vec::new(),
        };
        self.packets_seen += 1;
        let sealed = self.baseline_sealed();
        let ts = parsed.timestamp_ms / 1000;
        let mut out = Vec::new();

        let devices = store.list_devices().unwrap_or_default();
        let device_of = |ip: IpAddr| devices.iter().find(|d| d.ip == ip);
        let name = |ip: IpAddr| {
            device_of(ip)
                .and_then(|d| d.label.clone())
                .unwrap_or_else(|| ip.to_string())
        };

        // Rule 1 — new device (from the pipeline's discovery events).
        for event in packet_events {
            if event.kind == EventKind::DeviceDiscovered {
                if let Some(ip) = event.src_ip {
                    self.fire(
                        format!("new-device:{ip}"),
                        Alert {
                            timestamp: ts,
                            layer: "rules",
                            severity: Severity::Low,
                            title: format!("[new-device] New device appeared: {ip}"),
                            detail: "A device never seen before is active on the network. \
                                     Inventory it: if nobody can say what it is, it does not belong."
                                .to_string(),
                            device_ip: Some(ip),
                            factors: vec![("first seen in this packet".to_string(), 100)],
                        },
                        &mut out,
                    );
                }
            }
        }

        let (Some(src), Some(dst)) = (parsed.src_ip, parsed.dst_ip) else {
            return out;
        };

        // Rate window bookkeeping (feeds rule 6; baseline learns quietly).
        let window_len = {
            let window = self.windows.entry(src).or_default();
            window.push_back(ts);
            while window.front().map(|front| ts - front > RATE_WINDOW_S).unwrap_or(false) {
                window.pop_front();
            }
            window.len()
        };
        if !sealed {
            let entry = self.baseline_window_max.entry(src).or_insert(0);
            *entry = (*entry).max(window_len);
        }

        let src_level = device_of(src).and_then(|d| d.level);
        let dst_level = device_of(dst).and_then(|d| d.level);

        // Rule 5 — threat intel (either direction).
        for ip in [src, dst] {
            if self.intel.contains(&ip) {
                self.fire(
                    format!("threat-intel:{ip}"),
                    Alert {
                        timestamp: ts,
                        layer: "rules",
                        severity: Severity::High,
                        title: format!("[threat-intel] Traffic with listed address {ip}"),
                        detail: format!(
                            "{} communicated with {ip}, which is on the threat-intel list.",
                            name(src)
                        ),
                        device_ip: Some(ip),
                        factors: vec![("intel list match".to_string(), 100)],
                    },
                    &mut out,
                );
            }
        }

        // Rule 2 — IT (Level 4/5) straight to a Level 1 controller.
        if matches!(src_level, Some(PurdueLevel::Internet) | Some(PurdueLevel::Enterprise))
            && dst_level == Some(PurdueLevel::Control)
        {
            self.fire(
                format!("it-to-controller:{src}->{dst}"),
                Alert {
                    timestamp: ts,
                    layer: "rules",
                    severity: Severity::Critical,
                    title: format!(
                        "[it-to-controller] {} talked directly to {} (Level 1)",
                        name(src),
                        name(dst)
                    ),
                    detail: "IT-side devices must never reach controllers directly — that path \
                             skips the DMZ and every control in it. This is the shape of the \
                             Ukraine 2015 intrusion's final step."
                        .to_string(),
                    device_ip: Some(src),
                    factors: vec![("level 4/5 → level 1, no DMZ transit".to_string(), 100)],
                },
                &mut out,
            );
        }

        // Rule 4 — a level boundary crossed for the first time.
        if let (Some(a), Some(b)) = (src_level, dst_level) {
            if a != b {
                if !sealed {
                    self.baseline_pairs.insert((a, b));
                } else if !self.baseline_pairs.contains(&(a, b)) {
                    self.baseline_pairs.insert((a, b));
                    self.fire(
                        format!("new-level-crossing:{a:?}->{b:?}"),
                        Alert {
                            timestamp: ts,
                            layer: "rules",
                            severity: Severity::Medium,
                            title: format!(
                                "[new-level-crossing] First traffic across a boundary: {} → {}",
                                a.name(),
                                b.name()
                            ),
                            detail: format!(
                                "{} → {} traffic has never crossed this boundary in the baseline. \
                                 New conduits between zones are how intrusions spread.",
                                name(src),
                                name(dst)
                            ),
                            device_ip: Some(src),
                            factors: vec![("pair absent from baseline".to_string(), 100)],
                        },
                        &mut out,
                    );
                }
            }
        }

        // Rules 3 + 7 — Modbus writes.
        if let Some(mb) = parsed.modbus {
            if mb.is_write && !mb.is_response {
                let src_role = device_of(src).map(|d| d.role).unwrap_or(DeviceRole::Unknown);
                // Rule 3 — the writer is not an HMI / engineering station.
                if !matches!(src_role, DeviceRole::Hmi | DeviceRole::EngineeringStation) {
                    self.fire(
                        format!("write-from-non-hmi:{src}->{dst}"),
                        Alert {
                            timestamp: ts,
                            layer: "rules",
                            severity: Severity::Critical,
                            title: format!(
                                "[write-from-non-hmi] {} wrote to {}",
                                name(src),
                                name(dst)
                            ),
                            detail: "Only the HMI or engineering station should send write/control \
                                     commands to a controller. A write from anything else is the \
                                     Oldsmar pattern: an unexpected hand on the process."
                                .to_string(),
                            device_ip: Some(src),
                            factors: vec![(format!("writer role: {}", src_role.as_tag()), 100)],
                        },
                        &mut out,
                    );
                }
                // Rule 7 — this writer→target pair has never written.
                if !sealed {
                    self.write_pairs.insert((src, dst));
                } else if !self.write_pairs.contains(&(src, dst)) {
                    self.write_pairs.insert((src, dst));
                    self.fire(
                        format!("write-outside-pattern:{src}->{dst}"),
                        Alert {
                            timestamp: ts,
                            layer: "rules",
                            severity: Severity::High,
                            title: format!(
                                "[write-outside-pattern] {} wrote to {} — a first",
                                name(src),
                                name(dst)
                            ),
                            detail: "In all recorded history, this device has never written to \
                                     this controller. New write paths to controllers are how \
                                     attacks turn access into control."
                                .to_string(),
                            device_ip: Some(src),
                            factors: vec![("write pair absent from baseline".to_string(), 100)],
                        },
                        &mut out,
                    );
                }
            }
        }

        // Rule 6 — rate spike vs the source's own baseline window.
        if sealed && window_len >= RATE_FLOOR {
            let baseline = self.baseline_window_max.get(&src).copied().unwrap_or(0);
            if window_len as u64 >= 100 * (baseline as u64).max(1) || baseline == 0 {
                self.fire(
                    format!("rate-spike:{src}:{}", ts / 300),
                    Alert {
                        timestamp: ts,
                        layer: "rules",
                        severity: Severity::High,
                        title: format!(
                            "[rate-spike] {} sent {window_len} packets in {RATE_WINDOW_S} s",
                            name(src)
                        ),
                        detail: "Traffic at ~100× a device's normal rate (or a brand-new device \
                                 instantly flooding) is the signature of a scan, a malfunction, \
                                 or a denial-of-service against fragile controllers."
                            .to_string(),
                        device_ip: Some(src),
                        factors: vec![
                            (format!("window packets: {window_len}"), 60),
                            (format!("baseline window max: {baseline}"), 40),
                        ],
                    },
                    &mut out,
                );
            }
        }

        out
    }
}

impl DetectionLayer for RulesLayer {
    fn name(&self) -> &'static str {
        "rules"
    }

    fn evaluate(&mut self, _events: &[Event]) -> Vec<Alert> {
        // Rules evaluate packets (observe_packet), not event chunks;
        // the chunk path serves the anomaly and analyst layers.
        Vec::new()
    }
}

/// Layer 2 — statistical anomaly detection / early warning (Phase 5).
///
/// This is the layer Banning asked for by name at the start: *analyze
/// chunks of traffic and warn early, while an attacker is still
/// snooping.* It is statistics, not magic:
///
/// - Traffic is aggregated into [`CHUNK_S`]-second **chunks**.
/// - A **baseline** of normal is learned: who talks to whom (peers),
///   who writes, which Modbus functions each device uses, and how
///   much traffic each device normally makes per chunk.
/// - Each closed chunk is **scored** against the baseline with named,
///   weighted factors (new peer +25, never-seen function +20, write
///   from a device that never writes +25, …). A chunk scoring
///   ≥ [`ALERT_THRESHOLD`] raises an early-warning alert whose factors
///   are its receipts.
/// - The plant **risk score** is the latest chunk's score, decaying
///   ×0.7 per quiet chunk — a number that breathes instead of latching.
///
/// **Learning.** Peer/writer/device baselines seed from store history
/// (like the rules layer) and fold after every chunk. Function and
/// volume baselines need live chunks: until [`LEARN_CHUNKS`] chunks
/// have folded they are *excluded from alert scores* (they still show
/// in the status factors), and until the layer is trained — seeded
/// from ≥300 stored events or [`LEARN_CHUNKS`] live chunks — no
/// alerts fire at all. Function/volume baselines freeze once trained,
/// so a slow-ramping attacker cannot teach the layer that flooding
/// is normal. This layer, like the others, warns and never acts.
#[derive(Debug)]
pub struct AnomalyLayer {
    /// True while the layer is still learning (alerts suppressed).
    pub learning: bool,
    /// Current plant-wide risk score, 0 (normal) and up.
    pub risk_score: i32,
    /// device → peers it normally talks to.
    peers: std::collections::HashMap<IpAddr, std::collections::HashSet<IpAddr>>,
    /// Devices that ever write (Modbus) in the baseline.
    writers: std::collections::HashSet<IpAddr>,
    /// Devices present in the baseline.
    known_devices: std::collections::HashSet<IpAddr>,
    /// device → Modbus function codes it normally uses as a client.
    functions: std::collections::HashMap<IpAddr, std::collections::HashSet<u8>>,
    /// device → per-chunk packet counts seen during learning.
    volume_history: std::collections::HashMap<IpAddr, Vec<usize>>,
    /// True when function/volume baselines are complete and frozen.
    functions_frozen: bool,
    /// Chunks folded by this instance.
    chunks_folded: usize,
    /// Chunks scored (closed) by this instance.
    chunks_scored: usize,
    /// The open chunk being accumulated, if any.
    chunk: Option<ChunkAccum>,
    /// Factors of the most recently scored chunk (status display).
    last_factors: Vec<(String, i32)>,
    /// Title of the most recent early-warning alert, if any.
    last_alert_title: Option<String>,
}

/// Chunk length, in seconds of *capture* time.
pub const CHUNK_S: i64 = 30;
/// Live chunks that complete function/volume learning.
pub const LEARN_CHUNKS: usize = 6;
/// Chunk score at/above which an early warning fires.
pub const ALERT_THRESHOLD: i32 = 50;

/// Per-source aggregation inside one chunk.
#[derive(Debug, Default)]
struct SrcChunk {
    count: usize,
    peers: std::collections::HashSet<IpAddr>,
    functions: std::collections::HashSet<u8>,
    wrote: bool,
}

/// One open chunk of traffic being aggregated.
#[derive(Debug)]
struct ChunkAccum {
    start_ts: i64,
    per_src: std::collections::HashMap<IpAddr, SrcChunk>,
    new_devices: std::collections::HashSet<IpAddr>,
}

/// A snapshot of the anomaly layer for status displays.
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyStatus {
    /// Still learning (alerts suppressed).
    pub learning: bool,
    /// Current plant risk score.
    pub risk_score: i32,
    /// Chunks scored so far.
    pub chunks_scored: usize,
    /// Factors behind the most recent chunk score.
    pub last_factors: Vec<(String, i32)>,
    /// Most recent early-warning alert title, if any.
    pub last_alert_title: Option<String>,
}

impl Default for AnomalyLayer {
    fn default() -> AnomalyLayer {
        AnomalyLayer::new()
    }
}

impl AnomalyLayer {
    /// Creates an anomaly layer with an empty baseline, in learning mode.
    pub fn new() -> AnomalyLayer {
        AnomalyLayer {
            learning: true,
            risk_score: 0,
            peers: Default::default(),
            writers: Default::default(),
            known_devices: Default::default(),
            functions: Default::default(),
            volume_history: Default::default(),
            functions_frozen: false,
            chunks_folded: 0,
            chunks_scored: 0,
            chunk: None,
            last_factors: Vec::new(),
            last_alert_title: None,
        }
    }

    /// An anomaly layer whose peer/writer/device baselines are seeded
    /// from the store's history; with ≥[`BASELINE_EVENTS`] stored
    /// events it starts trained (function/volume factors still join
    /// alert scores only after live learning chunks freeze them).
    pub fn from_store(store: &crate::store::Store) -> AnomalyLayer {
        let mut layer = AnomalyLayer::new();
        if let Ok(devices) = store.list_devices() {
            layer.known_devices = devices.iter().map(|d| d.ip).collect();
        }
        if let Ok(connections) = store.list_connections() {
            for conn in &connections {
                layer.peers.entry(conn.src_ip).or_default().insert(conn.dst_ip);
                layer.peers.entry(conn.dst_ip).or_default().insert(conn.src_ip);
            }
        }
        if let Ok(pairs) = store.write_pairs() {
            layer.writers = pairs.iter().map(|(writer, _)| *writer).collect();
        }
        if store.event_count().unwrap_or(0) >= BASELINE_EVENTS {
            layer.learning = false;
        }
        layer
    }

    /// Status snapshot for the UI.
    pub fn status(&self) -> AnomalyStatus {
        AnomalyStatus {
            learning: self.learning,
            risk_score: self.risk_score,
            chunks_scored: self.chunks_scored,
            last_factors: self.last_factors.clone(),
            last_alert_title: self.last_alert_title.clone(),
        }
    }

    /// Feeds one packet (already processed by the pipeline) into the
    /// current chunk. When the packet's timestamp closes the chunk,
    /// the chunk is scored and an early-warning alert may be returned.
    pub fn observe_packet(
        &mut self,
        _store: &crate::store::Store,
        packet: &crate::source::Packet,
        packet_events: &[Event],
    ) -> Vec<Alert> {
        let parsed = match crate::parse::parse_packet(packet) {
            Ok(parsed) => parsed,
            Err(_) => return Vec::new(),
        };
        let ts = parsed.timestamp_ms / 1000;
        let mut out = Vec::new();
        if let Some(chunk) = &self.chunk {
            if ts >= chunk.start_ts + CHUNK_S {
                let closed = self.chunk.take().expect("checked above");
                out.extend(self.close_chunk(closed));
            }
        }
        if self.chunk.is_none() {
            self.chunk = Some(ChunkAccum {
                start_ts: ts,
                per_src: Default::default(),
                new_devices: Default::default(),
            });
        }
        let chunk = self.chunk.as_mut().expect("just set");
        for event in packet_events {
            if event.kind == EventKind::DeviceDiscovered {
                if let Some(ip) = event.src_ip {
                    chunk.new_devices.insert(ip);
                }
            }
        }
        if let (Some(src), Some(dst)) = (parsed.src_ip, parsed.dst_ip) {
            let entry = chunk.per_src.entry(src).or_default();
            entry.count += 1;
            entry.peers.insert(dst);
            if let Some(mb) = parsed.modbus {
                if !mb.is_response {
                    entry.functions.insert(mb.function_code);
                    if mb.is_write {
                        entry.wrote = true;
                    }
                }
            }
        }
        out
    }

    /// Scores a closed chunk against the baseline, folds it into the
    /// baseline (subject to the freeze rules), and returns an
    /// early-warning alert when the alert score clears the threshold.
    fn close_chunk(&mut self, chunk: ChunkAccum) -> Vec<Alert> {
        self.chunks_scored += 1;
        let mut best: Option<(IpAddr, i32, i32, Vec<(String, i32)>)> = None;
        for (src, agg) in &chunk.per_src {
            let mut display = 0i32;
            let mut alert_score = 0i32;
            let mut factors: Vec<(String, i32)> = Vec::new();
            // New peers.
            let baseline_peers = self.peers.get(src);
            let new_peers: Vec<IpAddr> = agg
                .peers
                .iter()
                .filter(|peer| !baseline_peers.map(|set| set.contains(peer)).unwrap_or(false))
                .copied()
                .collect();
            if !new_peers.is_empty() {
                let w = (25 * new_peers.len() as i32).min(50);
                display += w;
                alert_score += w;
                for peer in &new_peers {
                    factors.push((format!("new peer {peer}"), w / new_peers.len() as i32));
                }
            }
            // A device the baseline has never contained.
            if !self.known_devices.contains(src) {
                display += 20;
                alert_score += 20;
                factors.push(("device not in baseline".to_string(), 20));
            }
            // Never-seen functions (alert-counting only once frozen).
            let baseline_functions = self.functions.get(src);
            let new_functions: Vec<u8> = agg
                .functions
                .iter()
                .filter(|fc| !baseline_functions.map(|set| set.contains(fc)).unwrap_or(false))
                .copied()
                .collect();
            if !new_functions.is_empty() {
                let w = (20 * new_functions.len() as i32).min(40);
                display += w;
                if self.functions_frozen {
                    alert_score += w;
                }
                for fc in &new_functions {
                    factors.push((format!("never-seen function {fc}"), w / new_functions.len() as i32));
                }
            }
            // A write from a device that never writes.
            if agg.wrote && !self.writers.contains(src) {
                display += 25;
                alert_score += 25;
                factors.push(("write from a device that never writes".to_string(), 25));
            }
            // Volume vs the learned per-chunk mean (frozen track only).
            if self.functions_frozen {
                if let Some(history) = self.volume_history.get(src) {
                    if history.len() >= 3 {
                        let mean = history.iter().sum::<usize>() as f64 / history.len() as f64;
                        let count = agg.count as f64;
                        let w = if count > mean * 6.0 + 20.0 {
                            30
                        } else if count > mean * 3.0 + 10.0 {
                            15
                        } else {
                            0
                        };
                        if w > 0 {
                            display += w;
                            alert_score += w;
                            factors.push((format!("volume {:.0} vs normal {:.0}/chunk", count, mean), w));
                        }
                    }
                }
            }
            let better = match &best {
                Some((_, best_display, _, _)) => display > *best_display,
                None => true,
            };
            if better {
                best = Some((*src, display, alert_score, factors));
            }
        }

        let mut out = Vec::new();
        if let Some((src, display, alert_score, factors)) = best {
            self.last_factors = factors.clone();
            self.risk_score = if display >= self.risk_score {
                display
            } else {
                (self.risk_score as f64 * 0.7) as i32
            };
            if !self.learning && alert_score >= ALERT_THRESHOLD {
                let alert = Alert {
                    timestamp: chunk.start_ts,
                    layer: "anomaly",
                    severity: if alert_score >= 80 { Severity::High } else { Severity::Medium },
                    title: format!(
                        "[early-warning] Unusual traffic from {src} (score {alert_score})"
                    ),
                    detail: "This chunk of traffic does not match the learned baseline. \
                             Early warning means 'look now', not 'attack confirmed' — \
                             this is the shape of reconnaissance, before anything destructive."
                        .to_string(),
                    device_ip: Some(src),
                    factors,
                };
                self.last_alert_title = Some(alert.title.clone());
                out.push(alert);
            }
        } else {
            self.risk_score = (self.risk_score as f64 * 0.7) as i32;
        }

        // Fold the chunk into the baseline. Peers/writers/devices
        // always fold; functions/volumes fold only until they freeze.
        for (src, agg) in &chunk.per_src {
            self.peers.entry(*src).or_default().extend(agg.peers.iter().copied());
            if agg.wrote {
                self.writers.insert(*src);
            }
            self.known_devices.insert(*src);
            if !self.functions_frozen {
                self.functions.entry(*src).or_default().extend(agg.functions.iter().copied());
                self.volume_history.entry(*src).or_default().push(agg.count);
            }
        }
        self.chunks_folded += 1;
        if self.chunks_folded >= LEARN_CHUNKS {
            self.functions_frozen = true;
            self.learning = false;
        }
        out
    }
}

impl DetectionLayer for AnomalyLayer {
    fn name(&self) -> &'static str {
        "anomaly"
    }

    fn evaluate(&mut self, _events: &[Event]) -> Vec<Alert> {
        // The anomaly layer evaluates packets into chunks
        // (observe_packet), not event batches.
        Vec::new()
    }
}

/// Layer 3 — the optional local-LLM analyst.
///
/// Phase 6 implements this against a local model endpoint (e.g. Ollama
/// on the same machine). It receives only digested chunk summaries,
/// anomaly factors, and alert context — never a raw packet firehose.
/// Its output is narrative prose for a human, clearly labelled as
/// AI-generated interpretation.
#[derive(Debug, Default)]
pub struct AnalystLayer {
    /// Whether a local model endpoint is configured. Off/absent must
    /// never degrade the other layers.
    pub enabled: bool,
}

impl AnalystLayer {
    /// Creates a disabled analyst layer (the default).
    pub fn new() -> AnalystLayer {
        AnalystLayer { enabled: false }
    }
}

impl DetectionLayer for AnalystLayer {
    fn name(&self) -> &'static str {
        "analyst"
    }

    fn evaluate(&mut self, _events: &[Event]) -> Vec<Alert> {
        // Phase 6: summarise flagged chunks via the local model.
        Vec::new()
    }
}

/// The three layers wired in evaluation order — the engine's detector.
#[derive(Debug, Default)]
pub struct DetectionEngine {
    /// Layer 1: hard rules.
    pub rules: RulesLayer,
    /// Layer 2: anomaly early warning.
    pub anomaly: AnomalyLayer,
    /// Layer 3: optional LLM analyst.
    pub analyst: AnalystLayer,
}

impl DetectionEngine {
    /// Creates an engine with all three layers in their initial state.
    pub fn new() -> DetectionEngine {
        DetectionEngine {
            rules: RulesLayer::new(),
            anomaly: AnomalyLayer::new(),
            analyst: AnalystLayer::new(),
        }
    }

    /// Runs every layer over a chunk of events and collects all alerts,
    /// rules first (known-bad beats looks-weird beats narrative).
    pub fn evaluate(&mut self, events: &[Event]) -> Vec<Alert> {
        let mut alerts = Vec::new();
        alerts.extend(self.rules.evaluate(events));
        alerts.extend(self.anomaly.evaluate(events));
        alerts.extend(self.analyst.evaluate(events));
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EventKind;

    #[test]
    fn layers_report_their_names_in_order() {
        let engine = DetectionEngine::new();
        assert_eq!(engine.rules.name(), "rules");
        assert_eq!(engine.anomaly.name(), "anomaly");
        assert_eq!(engine.analyst.name(), "analyst");
    }

    #[test]
    fn phase_0_engine_alerts_on_nothing() {
        let mut engine = DetectionEngine::new();
        let events = vec![Event::new(0, EventKind::PacketObserved, "stub event")];
        assert!(engine.evaluate(&events).is_empty());
        assert!(engine.anomaly.learning);
        assert_eq!(engine.anomaly.risk_score, 0);
    }

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::High < Severity::Critical);
    }
}
