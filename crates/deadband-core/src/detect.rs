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

use crate::model::Event;
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

/// Layer 1 — hard rules. Phase 4 implements the initial rule set:
///
/// 1. new device appears · 2. IT-level device talks directly to a Level 1
/// controller · 3. controller receives a write from a non-HMI source ·
/// 4. traffic crosses a never-before-crossed level boundary · 5.
/// destination matches a threat-intel list · 6. device traffic rate
/// ≳100× normal · 7. Modbus write outside the normal command pattern.
#[derive(Debug, Default)]
pub struct RulesLayer {
    // Phase 4 state: known devices/connections snapshots, intel list.
}

impl RulesLayer {
    /// Creates an empty rules layer.
    pub fn new() -> RulesLayer {
        RulesLayer {}
    }
}

impl DetectionLayer for RulesLayer {
    fn name(&self) -> &'static str {
        "rules"
    }

    fn evaluate(&mut self, _events: &[Event]) -> Vec<Alert> {
        // Phase 4: run the rule set.
        Vec::new()
    }
}

/// Layer 2 — statistical anomaly detection / early warning.
///
/// Phase 5 implements: per-device and per-pair baselines (peers,
/// protocols, function codes, volumes, timing), chunk scoring, and a
/// per-device / per-plant risk score with contributing factors.
#[derive(Debug, Default)]
pub struct AnomalyLayer {
    /// True while the layer is still learning the baseline. Early
    /// warnings during learning are labelled as such in the UI rather
    /// than hidden — false positives are expected and named.
    pub learning: bool,
    /// Current plant-wide risk score, 0 (normal) and up.
    pub risk_score: i32,
}

impl AnomalyLayer {
    /// Creates an anomaly layer in learning mode with a zero score.
    pub fn new() -> AnomalyLayer {
        AnomalyLayer { learning: true, risk_score: 0 }
    }
}

impl DetectionLayer for AnomalyLayer {
    fn name(&self) -> &'static str {
        "anomaly"
    }

    fn evaluate(&mut self, _events: &[Event]) -> Vec<Alert> {
        // Phase 5: score the chunk against the baseline.
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
