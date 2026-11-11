//! Live packet capture (Phase 7) and the blind check (capture health).
//!
//! The libpcap parts live behind the `live-capture` cargo feature: this
//! VM has no system libpcap at all, so `cargo test -p deadband-core`
//! must keep building without it. The health check is pure logic and
//! is always compiled — and tested — here; the Mac build is the real
//! check for the pcap calls.
//!
//! Safety rules, as everywhere in this crate: passive only, forever.
//! Capture reads copies of traffic. It never transmits, never answers
//! a packet, never probes. The capture thread feeds the same
//! `process_packet_full` pipeline as the simulation and the replays,
//! so the rules layer, the anomaly layer and the analyst all run on
//! live traffic exactly as they do on the lab feeds.

use crate::model::{Event, EventKind};

/// Silence that means "the mirror port went quiet", in seconds. A
/// mirror port on a live segment sees *something* constantly; a full
/// minute of nothing after traffic was flowing is the #1 silent
/// failure a monitor can have, and it must scream.
pub const QUIET_AFTER_SECS: i64 = 60;

/// Window at startup: a capture that never sees a single packet in
/// its first minute is almost certainly on the wrong interface, or
/// the OS is refusing capture (macOS BPF permissions).
pub const STARTUP_QUIET_SECS: i64 = 60;

/// What the blind check says about a running capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureHealth {
    /// Traffic is flowing, or the capture just started and the
    /// startup window has not elapsed yet.
    Flowing,
    /// Running, saw traffic, then nothing for `QUIET_AFTER_SECS`.
    GoneQuiet,
    /// Running, never saw a packet in `STARTUP_QUIET_SECS`.
    NeverSawTraffic,
}

/// Pure decision: given the capture's counters, which state is it in?
/// `started_at_s` / `last_packet_at_s` are Unix seconds; `now_s` is
/// the current Unix second. A stopped capture has no opinion.
pub fn capture_health(
    running: bool,
    started_at_s: i64,
    last_packet_at_s: Option<i64>,
    packets_seen: u64,
    now_s: i64,
) -> CaptureHealth {
    if !running {
        return CaptureHealth::Flowing;
    }
    if packets_seen == 0 {
        if now_s - started_at_s >= STARTUP_QUIET_SECS {
            return CaptureHealth::NeverSawTraffic;
        }
        return CaptureHealth::Flowing;
    }
    match last_packet_at_s {
        Some(last) if now_s - last >= QUIET_AFTER_SECS => CaptureHealth::GoneQuiet,
        _ => CaptureHealth::Flowing,
    }
}

/// Builds the alert event the blind check raises — one per quiet
/// episode, recorded in the store like any other alert, so it shows
/// in the Events log, the bell and the latest-alert line. Returns
/// `None` when the capture is flowing (nothing to say).
pub fn health_alert_event(
    health: CaptureHealth,
    interface: &str,
    now_s: i64,
) -> Option<Event> {
    let summary = match health {
        CaptureHealth::Flowing => return None,
        CaptureHealth::GoneQuiet => format!(
            "Capture has gone quiet — no packets from {interface} for over a minute. \
             The sensor may be blind: check the mirror port / SPAN session, then the cable."
        ),
        CaptureHealth::NeverSawTraffic => format!(
            "Capture sees nothing — {interface} has delivered no packets since it started. \
             Check this is the right interface, and that the Mac allows capture (see Live capture help)."
        ),
    };
    Some(Event::new(now_s, EventKind::AlertRaised, summary))
}

/// One network interface libpcap can capture on.
#[cfg(feature = "live-capture")]
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// OS name, e.g. `en0`.
    pub name: String,
    /// Human description when libpcap has one.
    pub description: Option<String>,
    /// Addresses assigned to the interface, as strings.
    pub addresses: Vec<String>,
}

/// The interfaces libpcap can see. Listing needs no capture
/// permission, so this works even before the BPF flow is done.
#[cfg(feature = "live-capture")]
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, String> {
    let devices = pcap::Device::list().map_err(|e| format!("Could not list interfaces: {e}"))?;
    Ok(devices
        .into_iter()
        .map(|d| InterfaceInfo {
            name: d.name,
            description: d.desc,
            addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
        })
        .collect())
}

/// Opens an interface for live capture: promiscuous (a mirror port
/// carries other devices' traffic, and promiscuous mode is what lets
/// us see it), full snap length, 100 ms read timeout so the feed
/// thread can check its stop flag regularly. Errors are plain
/// English; a permission refusal names the macOS BPF step.
#[cfg(feature = "live-capture")]
pub fn open_interface(name: &str) -> Result<pcap::Capture<pcap::Active>, String> {
    let devices = pcap::Device::list().map_err(|e| format!("Could not list interfaces: {e}"))?;
    let device = devices
        .into_iter()
        .find(|d| d.name == name)
        .ok_or_else(|| {
            let known: Vec<String> = pcap::Device::list()
                .map(|ds| ds.into_iter().map(|d| d.name).collect())
                .unwrap_or_default();
            format!(
                "No interface named {name}. Available: {}",
                if known.is_empty() { "(none found)".to_string() } else { known.join(", ") }
            )
        })?;
    let capture = pcap::Capture::from_device(device)
        .map_err(|e| format!("Could not open {name}: {e}"))?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .open()
        .map_err(|e| {
            let detail = e.to_string();
            if detail.to_lowercase().contains("permission") {
                format!(
                    "macOS refused capture on {name} ({detail}). The Mac needs BPF access: \
                     join the access_bpf group (see docs/live-capture.md) or run the app with sudo for a lab test."
                )
            } else {
                format!("Could not start capture on {name}: {detail}")
            }
        })?;
    Ok(capture)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_flowing_when_stopped() {
        assert_eq!(
            capture_health(false, 1_000, Some(1_000), 50, 1_500),
            CaptureHealth::Flowing
        );
    }

    #[test]
    fn health_flowing_just_started() {
        // Running, nothing yet, but the startup window has not elapsed.
        assert_eq!(
            capture_health(true, 1_000, None, 0, 1_030),
            CaptureHealth::Flowing
        );
    }

    #[test]
    fn health_silent_at_startup() {
        assert_eq!(
            capture_health(true, 1_000, None, 0, 1_060),
            CaptureHealth::NeverSawTraffic
        );
        assert_eq!(
            capture_health(true, 1_000, None, 0, 1_061),
            CaptureHealth::NeverSawTraffic
        );
    }

    #[test]
    fn health_flowing_while_traffic_arrives() {
        assert_eq!(
            capture_health(true, 1_000, Some(1_090), 120, 1_100),
            CaptureHealth::Flowing
        );
    }

    #[test]
    fn health_quiet_after_a_minute_silence() {
        assert_eq!(
            capture_health(true, 1_000, Some(1_000), 120, 1_059),
            CaptureHealth::Flowing
        );
        assert_eq!(
            capture_health(true, 1_000, Some(1_000), 120, 1_060),
            CaptureHealth::GoneQuiet
        );
    }

    #[test]
    fn health_alert_event_only_when_unhealthy() {
        assert!(health_alert_event(CaptureHealth::Flowing, "en0", 1_000).is_none());
        let quiet = health_alert_event(CaptureHealth::GoneQuiet, "en0", 1_000).unwrap();
        assert_eq!(quiet.kind, EventKind::AlertRaised);
        assert!(quiet.summary.contains("gone quiet"));
        assert!(quiet.summary.contains("en0"));
        let silent =
            health_alert_event(CaptureHealth::NeverSawTraffic, "en0", 1_000).unwrap();
        assert!(silent.summary.contains("sees nothing"));
    }
}
