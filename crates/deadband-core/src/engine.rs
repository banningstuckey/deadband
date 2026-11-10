//! The pipeline: packet in → parse → inventory, connections, events →
//! store. This is the one path every traffic source flows through, so
//! the simulated plant, a replayed capture, and a live sensor are
//! indistinguishable to everything downstream.
//!
//! Phase 1 scope: discovery events for new devices and connections,
//! one event per Modbus command, quiet packet events for the rest.
//! Detection layers (Phase 4+) hook in after storage.

use crate::model::{Connection, Device, Event, EventKind, Protocol};
use crate::parse::{parse_packet, ParsedPacket};
use crate::source::Packet;
use crate::store::Store;
use std::net::IpAddr;

/// Processes one raw packet end to end, storing everything it learns.
/// Returns the events it produced (already stored, ids set) so the UI
/// can stream them live. Unparseable packets produce no events —
/// Phase 3 decides what to do with genuinely broken traffic.
pub fn process_packet(store: &Store, packet: &Packet) -> Vec<Event> {
    let parsed = match parse_packet(packet) {
        Ok(parsed) => parsed,
        Err(_) => return Vec::new(),
    };
    let timestamp_s = parsed.timestamp_ms / 1000;
    let mut events = Vec::new();

    // Device discovery: any endpoint never seen before joins the
    // inventory and raises a discovery event.
    for ip in [parsed.src_ip, parsed.dst_ip].into_iter().flatten() {
        if !store.device_exists(ip).unwrap_or(true) {
            let _ = store.add_device(&Device::new(ip, timestamp_s));
            let mut event = Event::new(
                timestamp_s,
                EventKind::DeviceDiscovered,
                format!("New device seen: {ip}"),
            );
            event.src_ip = Some(ip);
            events.push(event);
        }
    }

    let (src_ip, dst_ip) = match (parsed.src_ip, parsed.dst_ip) {
        (Some(src), Some(dst)) => (src, dst),
        _ => return finish(store, events),
    };

    // Connection accounting. Modbus responses are folded back into the
    // client's conversation (client → server), so a poll and its reply
    // are one connection, not two.
    let is_response = parsed.modbus.map(|mb| mb.is_response).unwrap_or(false);
    let (client, server, server_port) = if is_response {
        (dst_ip, src_ip, parsed.src_port.unwrap_or(0))
    } else {
        (src_ip, dst_ip, parsed.dst_port.unwrap_or(0))
    };
    let connection = Connection {
        id: None,
        src_ip: client,
        dst_ip: server,
        dst_port: server_port,
        protocol: parsed.protocol,
        first_seen: timestamp_s,
        last_seen: timestamp_s,
        packet_count: 1,
        byte_count: parsed.length as u64,
    };
    if let Ok(true) = store.record_connection(&connection) {
        let mut event = Event::new(
            timestamp_s,
            EventKind::ConnectionObserved,
            format!(
                "New connection: {} → {}:{} ({})",
                name_of(store, client),
                name_of(store, server),
                server_port,
                parsed.protocol.as_tag(),
            ),
        );
        event.src_ip = Some(client);
        event.dst_ip = Some(server);
        events.push(event);
    }

    // The headline event for this packet.
    events.push(packet_event(store, &parsed, src_ip, dst_ip, timestamp_s));
    finish(store, events)
}

/// [`process_packet`], plus the rules layer: alerts raised on this
/// packet are converted to alert events, stored, and returned with
/// the packet's own events (alerts last). The rules layer keeps its
/// session state (baseline, dedup) in the caller's hands, so each
/// feed — simulation, replay, scenario, future live capture — owns
/// one, constructed via [`crate::detect::RulesLayer::from_store`].
pub fn process_packet_with_rules(
    store: &Store,
    packet: &Packet,
    rules: &mut crate::detect::RulesLayer,
) -> Vec<Event> {
    let mut events = process_packet(store, packet);
    let alerts = rules.observe_packet(store, packet, &events);
    if !alerts.is_empty() {
        let parsed = parse_packet(packet).ok();
        let alert_events: Vec<Event> = alerts
            .iter()
            .map(|alert| {
                let mut event = Event::new(
                    alert.timestamp,
                    EventKind::AlertRaised,
                    format!("{} — {}", alert.title, alert.detail),
                );
                event.src_ip = alert.device_ip;
                event.dst_ip = parsed.as_ref().and_then(|p| p.dst_ip);
                event
            })
            .collect();
        events.extend(finish(store, alert_events));
    }
    events
}

/// Builds the per-packet event: Modbus commands get the full sentence,
/// responses and plain traffic get a quieter one.
fn packet_event(
    store: &Store,
    parsed: &ParsedPacket,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    timestamp_s: i64,
) -> Event {
    let src = name_of(store, src_ip);
    let dst = name_of(store, dst_ip);
    let (kind, summary) = match parsed.modbus {
        Some(mb) if mb.is_response => (
            EventKind::PacketObserved,
            format!(
                "{src} → {dst}: {} response{}",
                mb.function_name(),
                if mb.is_exception { " (exception!)" } else { "" },
            ),
        ),
        Some(mb) => {
            let detail = match (mb.address, mb.quantity, mb.value) {
                (Some(addr), Some(qty), _) => format!("@ {addr} × {qty}"),
                (Some(addr), _, Some(value)) => format!("@ {addr} = {value}"),
                _ => String::new(),
            };
            (
                EventKind::ModbusCommand { function_code: mb.function_code, is_write: mb.is_write },
                format!(
                    "{src} → {dst}: {}{} {detail}",
                    if mb.is_write { "WRITE — " } else { "" },
                    mb.function_name(),
                ),
            )
        }
        None => (
            EventKind::PacketObserved,
            format!(
                "{src} → {dst}: {}/{} ({} bytes)",
                match parsed.protocol {
                    Protocol::Udp => "UDP",
                    _ => "TCP",
                },
                parsed.dst_port.unwrap_or(0),
                parsed.length,
            ),
        ),
    };
    let mut event = Event::new(timestamp_s, kind, summary);
    event.src_ip = Some(src_ip);
    event.dst_ip = Some(dst_ip);
    event
}

/// Stores the events and returns them with ids assigned.
fn finish(store: &Store, mut events: Vec<Event>) -> Vec<Event> {
    for event in &mut events {
        if let Ok(id) = store.record_event(event) {
            event.id = Some(id);
        }
    }
    events
}

/// Human name for an IP: the inventory label when known
/// ("Line 1 PLC"), else the bare address. With a handful of devices,
/// reading the inventory per packet is fine; Phase 3 can cache.
fn name_of(store: &Store, ip: IpAddr) -> String {
    match store.list_devices() {
        Ok(devices) => devices
            .iter()
            .find(|device| device.ip == ip)
            .and_then(|device| device.label.clone())
            .unwrap_or_else(|| ip.to_string()),
        Err(_) => ip.to_string(),
    }
}

/// Snapshot of what the pipeline has accumulated, for status displays.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineStats {
    pub devices: i64,
    pub events: i64,
}

pub fn stats(store: &Store) -> PipelineStats {
    PipelineStats {
        devices: store.device_count().unwrap_or(0),
        events: store.event_count().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim;
    use crate::source::{SimulatedSource, TrafficSource};

    #[test]
    fn simulated_plant_flows_through_the_pipeline() {
        let store = Store::open_in_memory().unwrap();
        // Pre-register the roster, as the app shell does at startup:
        // discovery then has ground truth to name.
        for device in sim::roster() {
            store.add_device(&device).unwrap();
        }
        let mut source = SimulatedSource::new(1_700_000_000_000);
        let mut modbus_commands = 0;
        let mut writes = 0;
        for _ in 0..300 {
            let packet = source.next_packet().unwrap();
            for event in process_packet(&store, &packet) {
                match event.kind {
                    EventKind::ModbusCommand { is_write, .. } => {
                        modbus_commands += 1;
                        if is_write {
                            writes += 1;
                            assert!(event.summary.contains("Operator HMI"), "{}", event.summary);
                        }
                    }
                    _ => {}
                }
            }
        }
        let stats = stats(&store);
        assert_eq!(stats.devices, 5);
        assert!(stats.events > 250, "events stored: {}", stats.events);
        assert!(modbus_commands > 50, "commands seen: {modbus_commands}");
        assert!(writes >= 1, "at least one setpoint write in 300 packets");
    }

    #[test]
    fn normal_plant_traffic_raises_no_alerts() {
        // The false-positive discipline: 400 packets of ordinary plant
        // operation, rules armed, must produce zero alerts.
        let store = Store::open_in_memory().unwrap();
        for device in sim::roster() {
            store.add_device(&device).unwrap();
        }
        let mut rules = crate::detect::RulesLayer::new();
        let mut source = SimulatedSource::new(1_700_000_000_000);
        let mut alerts = 0;
        for _ in 0..400 {
            let packet = source.next_packet().unwrap();
            for event in process_packet_with_rules(&store, &packet, &mut rules) {
                if event.kind == EventKind::AlertRaised {
                    alerts += 1;
                }
            }
        }
        assert_eq!(alerts, 0, "normal traffic must never alert");
        assert!(rules.baseline_sealed(), "baseline seals during the run");
    }

    #[test]
    fn sample_replay_flags_the_laptop() {
        // The Phase 3 sample was bait; the rules are the trap. The
        // foreign laptop must be flagged for writing, and every one of
        // the six foreign devices announced as new.
        let store = Store::open_in_memory().unwrap();
        let mut rules = crate::detect::RulesLayer::new();
        let mut new_devices = 0;
        let mut laptop_write_alerts = 0;
        for packet in crate::sample::sample_packets() {
            for event in process_packet_with_rules(&store, &packet, &mut rules) {
                if event.kind == EventKind::AlertRaised {
                    if event.summary.contains("[new-device]") {
                        new_devices += 1;
                    }
                    if event.summary.contains("192.168.50.77")
                        && (event.summary.contains("[write-from-non-hmi]")
                            || event.summary.contains("[write-outside-pattern]"))
                    {
                        laptop_write_alerts += 1;
                    }
                }
            }
        }
        assert_eq!(new_devices, 6, "all six foreign devices announced");
        assert_eq!(laptop_write_alerts, 2, "the laptop's write trips rules 3 and 7");
    }

    #[test]
    fn threat_intel_address_alerts() {
        let store = Store::open_in_memory().unwrap();
        let mut rules = crate::detect::RulesLayer::new();
        let frame = sim::build_tcp_frame(
            "02:db:00:00:04:0a",
            "02:db:00:00:03:20",
            [10, 0, 4, 10],
            [203, 0, 113, 66],
            51000,
            443,
            b"beacon",
            1,
        );
        let events = process_packet_with_rules(
            &store,
            &Packet { timestamp_ms: 60_000, data: frame },
            &mut rules,
        );
        assert!(
            events.iter().any(|e| e.summary.contains("[threat-intel]")),
            "{events:?}"
        );
    }

    #[test]
    fn unknown_device_is_discovered_from_traffic() {
        let store = Store::open_in_memory().unwrap();
        let frame = sim::build_tcp_frame(
            "02:db:00:00:09:09",
            "02:db:00:00:03:20",
            [10, 9, 9, 9],
            [10, 0, 3, 20],
            51000,
            443,
            b"ping",
            1,
        );
        let events = process_packet(&store, &Packet { timestamp_ms: 60_000, data: frame });
        assert!(events.iter().any(|e| e.kind == EventKind::DeviceDiscovered));
        assert!(store.device_exists("10.9.9.9".parse().unwrap()).unwrap());
    }
}
