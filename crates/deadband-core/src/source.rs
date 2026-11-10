//! Traffic sources: where packets enter the pipeline.
//!
//! **The safety rule lives here.** Every implementation of
//! [`TrafficSource`] obtains a *copy* of traffic — it never transmits
//! into the monitored network. No scanning, no probing, no ARP requests,
//! no responses. If a future source idea requires sending even one packet
//! into a plant network, it does not belong in this module.
//!
//! Planned sources, in build order:
//!
//! 1. [`SimulatedSource`] — the built-in virtual plant (Phase 1). The
//!    lab that proves every other phase without touching real equipment.
//! 2. PCAP replay — public ICS capture files played through the same
//!    pipeline in real time (Phase 3).
//! 3. Live capture — a mirrored/SPAN port or the host's own interface,
//!    read-only at the OS level (Phase 7).

/// One raw packet as handed to the parser: capture time plus the bytes
/// exactly as they appeared on the wire (starting at the Ethernet header
/// for framed captures; later sources may note other link types here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Capture time, Unix milliseconds.
    pub timestamp_ms: i64,
    /// Raw frame bytes.
    pub data: Vec<u8>,
}

/// A passive source of packets. Implementations are pull-based: the
/// engine asks for the next packet, the source never pushes — and never,
/// ever transmits.
pub trait TrafficSource: Send {
    /// Short identifier shown in the UI ("simulated", "pcap", "live:en0").
    fn name(&self) -> &str;

    /// Returns the next packet, or `None` when the source is exhausted
    /// (end of a replay file) or idle (live sources return `None` when
    /// polled with nothing captured yet — the caller decides pacing).
    fn next_packet(&mut self) -> Option<Packet>;
}

/// The built-in simulated plant's traffic source.
///
/// Wraps [`crate::sim::Plant`]: every call produces the plant's next
/// real frame, stamped `base_ms + virtual clock`. The plant never runs
/// dry (there is always a next poll), so this source never returns
/// `None`; the caller paces itself.
pub struct SimulatedSource {
    base_ms: i64,
    plant: crate::sim::Plant,
}

impl SimulatedSource {
    /// A simulated plant whose virtual clock starts at Unix
    /// millisecond `base_ms` (the Tauri shell passes "now" so stored
    /// events carry real-world timestamps).
    pub fn new(base_ms: i64) -> SimulatedSource {
        SimulatedSource { base_ms, plant: crate::sim::Plant::new() }
    }
}

impl TrafficSource for SimulatedSource {
    fn name(&self) -> &str {
        "simulated"
    }

    fn next_packet(&mut self) -> Option<Packet> {
        Some(self.plant.next_packet(self.base_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_source_streams_plant_frames() {
        let mut source = SimulatedSource::new(5_000);
        assert_eq!(source.name(), "simulated");
        let first = source.next_packet().expect("plant always has traffic");
        assert!(first.timestamp_ms >= 5_000);
        assert!(!first.data.is_empty());
        let second = source.next_packet().unwrap();
        assert!(second.timestamp_ms >= first.timestamp_ms);
    }
}
