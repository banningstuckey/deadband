//! # deadband-core
//!
//! The monitoring engine for **Deadband**, a real-time, passive OT
//! (operational technology) network monitor, as a standalone library.
//!
//! The engine is deliberately independent of any UI. The Tauri desktop app
//! in `src-tauri` is only its first shell; the same crate can later power a
//! headless sensor on a small Linux box inside a plant.
//!
//! ## Pipeline
//!
//! ```text
//! source ──► parse ──► model (events) ──► store (SQLite)
//!                                            │
//!                                            ▼
//!                              detect (rules → anomaly → analyst)
//!                                            │
//!                                            ▼
//!                                     alerts for the UI
//! ```
//!
//! Every traffic source feeds the *same* pipeline. The engine cannot tell
//! (and does not care) whether packets came from the built-in simulated
//! plant, a replayed packet capture, or a live mirrored port.
//!
//! ## Safety rules (non-negotiable, apply to every module)
//!
//! 1. **Passive only, forever.** Nothing in this crate ever transmits into
//!    a monitored network: no scanning, no probing, no responses. Sources
//!    read copies of traffic only.
//! 2. **AI warns, AI never acts.** Detection layers produce alerts and
//!    explanations. They never block, disconnect, or reconfigure anything.
//! 3. **Local first, no cloud.** All data stays on the user's machine.

pub mod detect;
pub mod model;
pub mod parse;
pub mod source;
pub mod store;

/// Snapshot of engine identity/health, surfaced to the UI so the frontend
/// can prove the Rust ↔ UI bridge works and display what it is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineStatus {
    /// Product name.
    pub name: &'static str,
    /// Engine (crate) version.
    pub version: &'static str,
    /// Development phase of the whole product.
    pub phase: &'static str,
    /// The three detection layers, in evaluation order.
    pub detection_layers: [&'static str; 3],
}

/// Returns the current engine status. Phase 0: static identity values.
/// Later phases add live counters (devices seen, events stored, …).
pub fn engine_status() -> EngineStatus {
    EngineStatus {
        name: "Deadband",
        version: env!("CARGO_PKG_VERSION"),
        phase: "Phase 0 — skeleton",
        detection_layers: ["rules", "anomaly", "analyst"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_identity() {
        let status = engine_status();
        assert_eq!(status.name, "Deadband");
        assert_eq!(status.detection_layers.len(), 3);
        assert!(status.phase.starts_with("Phase 0"));
    }
}
