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
/// Phase 0 stub: yields nothing. Phase 1 makes it generate realistic
/// Modbus/TCP + ordinary IP traffic from a virtual office PC, historian,
/// HMI, and PLCs, on a believable schedule — real packets into the real
/// parser, so the GUI is never faking its data.
#[derive(Debug, Default)]
pub struct SimulatedSource {
    // Phase 1 state goes here: virtual device roster, poll schedule,
    // scenario runner.
}

impl SimulatedSource {
    /// Creates an idle simulated source.
    pub fn new() -> SimulatedSource {
        SimulatedSource {}
    }
}

impl TrafficSource for SimulatedSource {
    fn name(&self) -> &str {
        "simulated"
    }

    fn next_packet(&mut self) -> Option<Packet> {
        // Phase 1: emit the virtual plant's scheduled traffic.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_source_is_named_and_idle_in_phase_0() {
        let mut source = SimulatedSource::new();
        assert_eq!(source.name(), "simulated");
        assert_eq!(source.next_packet(), None);
    }
}
