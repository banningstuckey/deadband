//! Lab attack scenarios: scripted packet sequences that imitate the
//! shape of real intrusions, so the rules layer can be exercised —
//! and proven — on demand. These run ONLY inside the built-in lab
//! (the simulator's address space); nothing here can emit traffic
//! anywhere else, in keeping with the passive-only rule: scenarios
//! *generate frames for the pipeline*, they never touch a network.
//!
//! The scripts are original code written from public reporting:
//! - `rogue-laptop` — the Oldsmar (2021) shape: an unknown device
//!   appears and writes a dangerous setpoint to a controller.
//! - `office-reachdown` — the Ukraine (2015) shape: an IT workstation
//!   reaches past every boundary and touches a controller directly.
//! - `recon-sweep` — the reconnaissance phase every intrusion starts
//!   with: one unknown device interrogating everything, fast.

use crate::sim::{
    build_modbus_read, build_modbus_read_response, build_modbus_write_single, build_tcp_frame,
    PlantDevice, HISTORIAN, HMI, OFFICE_PC, PLC1, PLC2,
};
use crate::source::Packet;

/// One scenario's UI metadata.
#[derive(Debug, Clone, Copy)]
pub struct ScenarioInfo {
    /// Stable id used by the UI ("rogue-laptop").
    pub id: &'static str,
    /// Button title.
    pub title: &'static str,
    /// What it imitates and what should catch it.
    pub blurb: &'static str,
}

/// All scenarios, in presentation order.
pub fn catalog() -> Vec<ScenarioInfo> {
    vec![
        ScenarioInfo {
            id: "rogue-laptop",
            title: "Rogue laptop writes to a PLC",
            blurb: "An unregistered laptop (10.0.9.77) polls Line 1, then writes setpoint 999. \
                    Should trip: new device, write from a non-HMI, write outside the pattern.",
        },
        ScenarioInfo {
            id: "office-reachdown",
            title: "Office PC reaches down to Level 1",
            blurb: "The Level 4 office PC talks straight to a Level 1 PLC and tries a write. \
                    Should trip: IT-to-controller, new level crossing, write from a non-HMI.",
        },
        ScenarioInfo {
            id: "recon-sweep",
            title: "Recon sweep",
            blurb: "An unknown device (10.0.9.99) interrogates every plant device, fast. \
                    Should trip: new device, traffic rate spike.",
        },
        ScenarioInfo {
            id: "slow-recon",
            title: "Slow recon (probing only)",
            blurb: "An unknown device (10.0.9.55) quietly probes with unusual function codes \
                    over ~90 seconds — no writes, nothing destructive. The rules only note a \
                    new device; the anomaly layer's early warning is built to catch this. \
                    Works best after the plant has run a few minutes (baseline trained).",
        },
    ]
}

const LAPTOP: PlantDevice = PlantDevice {
    ip: [10, 0, 9, 77],
    mac: "02:db:00:00:09:4d",
    level: crate::model::PurdueLevel::Supervisory,
    role: crate::model::DeviceRole::Unknown,
    label: "Rogue laptop",
};
const SWEEPER: PlantDevice = PlantDevice {
    ip: [10, 0, 9, 99],
    mac: "02:db:00:00:09:63",
    level: crate::model::PurdueLevel::Supervisory,
    role: crate::model::DeviceRole::Unknown,
    label: "Sweeper",
};
const PROBER: PlantDevice = PlantDevice {
    ip: [10, 0, 9, 55],
    mac: "02:db:00:00:09:37",
    level: crate::model::PurdueLevel::Supervisory,
    role: crate::model::DeviceRole::Unknown,
    label: "Prober",
};
const LAPTOP_PORT: u16 = 40077;
const SWEEPER_PORT: u16 = 40099;
const PROBER_PORT: u16 = 40055;
const OFFICE_PORT: u16 = 51000;

fn modbus_adu(transaction: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut adu = Vec::with_capacity(7 + pdu.len());
    adu.extend_from_slice(&transaction.to_be_bytes());
    adu.extend_from_slice(&0u16.to_be_bytes());
    adu.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    adu.push(unit);
    adu.extend_from_slice(pdu);
    adu
}

/// A write-single-register echo response (server → client).
fn write_echo(server: PlantDevice, client: PlantDevice, client_port: u16, address: u16, value: u16, seq: u32) -> Vec<u8> {
    let mut pdu = vec![6u8];
    pdu.extend_from_slice(&address.to_be_bytes());
    pdu.extend_from_slice(&value.to_be_bytes());
    let adu = modbus_adu((seq & 0xFFFF) as u16, 1, &pdu);
    build_tcp_frame(server.mac, client.mac, server.ip, client.ip, 502, client_port, &adu, seq)
}

fn read_pair(
    out: &mut Vec<Packet>,
    base_ms: i64,
    at_ms: i64,
    client: PlantDevice,
    client_port: u16,
    server: PlantDevice,
    seq: u32,
) {
    out.push(Packet {
        timestamp_ms: base_ms + at_ms,
        data: build_modbus_read(client.mac, server.mac, client.ip, server.ip, client_port, 1, 3, 0, 4, seq),
    });
    out.push(Packet {
        timestamp_ms: base_ms + at_ms + 12,
        data: build_modbus_read_response(
            server.mac, client.mac, server.ip, client.ip, client_port, 1, 3, &[11, 22, 33, 44], seq + 1,
        ),
    });
}

fn packets_rogue_laptop(base_ms: i64) -> Vec<Packet> {
    let mut out = Vec::new();
    read_pair(&mut out, base_ms, 0, LAPTOP, LAPTOP_PORT, PLC1, 7000);
    read_pair(&mut out, base_ms, 900, LAPTOP, LAPTOP_PORT, PLC1, 7002);
    out.push(Packet {
        timestamp_ms: base_ms + 1800,
        data: build_modbus_write_single(LAPTOP.mac, PLC1.mac, LAPTOP.ip, PLC1.ip, LAPTOP_PORT, 1, 200, 999, 7004),
    });
    out.push(Packet {
        timestamp_ms: base_ms + 1812,
        data: write_echo(PLC1, LAPTOP, LAPTOP_PORT, 200, 999, 7005),
    });
    out
}

fn packets_office_reachdown(base_ms: i64) -> Vec<Packet> {
    let mut out = Vec::new();
    read_pair(&mut out, base_ms, 0, OFFICE_PC, OFFICE_PORT, PLC1, 8000);
    out.push(Packet {
        timestamp_ms: base_ms + 800,
        data: build_modbus_write_single(
            OFFICE_PC.mac, PLC1.mac, OFFICE_PC.ip, PLC1.ip, OFFICE_PORT, 1, 200, 55, 8002,
        ),
    });
    out.push(Packet {
        timestamp_ms: base_ms + 812,
        data: write_echo(PLC1, OFFICE_PC, OFFICE_PORT, 200, 55, 8003),
    });
    out
}

fn packets_recon_sweep(base_ms: i64) -> Vec<Packet> {
    let targets = [PLC1, PLC2, HISTORIAN, HMI];
    let mut out = Vec::new();
    let mut seq = 9000u32;
    for round in 0..25i64 {
        for (index, target) in targets.iter().enumerate() {
            let at = round * 180 + index as i64 * 45;
            out.push(Packet {
                timestamp_ms: base_ms + at,
                data: build_modbus_read(
                    SWEEPER.mac, target.mac, SWEEPER.ip, target.ip, SWEEPER_PORT, 1, 3, 0, 4, seq,
                ),
            });
            seq += 1;
            // Controllers and the historian answer; the HMI does not serve.
            if target.ip != HMI.ip {
                out.push(Packet {
                    timestamp_ms: base_ms + at + 12,
                    data: build_modbus_read_response(
                        target.mac, SWEEPER.mac, target.ip, SWEEPER.ip, SWEEPER_PORT, 1, 3,
                        &[7, 8, 9, 10], seq,
                    ),
                });
                seq += 1;
            }
        }
    }
    out.sort_by_key(|p| p.timestamp_ms);
    out
}

fn read_pair_fc(
    out: &mut Vec<Packet>,
    base_ms: i64,
    at_ms: i64,
    client: PlantDevice,
    client_port: u16,
    server: PlantDevice,
    function: u8,
    seq: u32,
) {
    out.push(Packet {
        timestamp_ms: base_ms + at_ms,
        data: build_modbus_read(client.mac, server.mac, client.ip, server.ip, client_port, 1, function, 0, 4, seq),
    });
    out.push(Packet {
        timestamp_ms: base_ms + at_ms + 12,
        data: build_modbus_read_response(
            server.mac, client.mac, server.ip, client.ip, client_port, 1, function, &[5, 6, 7, 8], seq + 1,
        ),
    });
}

fn packets_slow_recon(base_ms: i64) -> Vec<Packet> {
    // Probing only: varied read functions, two controllers, long
    // pauses, one ordinary-looking web request. Nothing writes.
    let mut out = Vec::new();
    read_pair_fc(&mut out, base_ms, 0, PROBER, PROBER_PORT, PLC1, 1, 9500);
    read_pair_fc(&mut out, base_ms, 20_000, PROBER, PROBER_PORT, PLC2, 2, 9502);
    read_pair_fc(&mut out, base_ms, 45_000, PROBER, PROBER_PORT, PLC1, 4, 9504);
    read_pair_fc(&mut out, base_ms, 70_000, PROBER, PROBER_PORT, PLC2, 1, 9506);
    out.push(Packet {
        timestamp_ms: base_ms + 95_000,
        data: build_tcp_frame(
            PROBER.mac, HISTORIAN.mac, PROBER.ip, HISTORIAN.ip, PROBER_PORT, 443,
            b"GET / HTTP/1.0\r\n\r\n", 9508,
        ),
    });
    out
}

/// The packet script for a scenario id, or `None` for an unknown id.
/// Timestamps start at `base_ms` (the shell passes "now").
pub fn packets(name: &str, base_ms: i64) -> Option<Vec<Packet>> {
    match name {
        "rogue-laptop" => Some(packets_rogue_laptop(base_ms)),
        "office-reachdown" => Some(packets_office_reachdown(base_ms)),
        "recon-sweep" => Some(packets_recon_sweep(base_ms)),
        "slow-recon" => Some(packets_slow_recon(base_ms)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::RulesLayer;
    use crate::engine;
    use crate::model::EventKind;
    use crate::sim;
    use crate::source::{SimulatedSource, TrafficSource};
    use crate::store::Store;

    /// A store with real history: the roster registered and 300
    /// packets of normal plant traffic processed.
    fn store_with_history() -> Store {
        let store = Store::open_in_memory().unwrap();
        for device in sim::roster() {
            store.add_device(&device).unwrap();
        }
        let mut source = SimulatedSource::new(1_700_000_000_000);
        for _ in 0..300 {
            let packet = source.next_packet().unwrap();
            engine::process_packet(&store, &packet);
        }
        store
    }

    fn alert_titles(events: &[crate::model::Event]) -> Vec<String> {
        events
            .iter()
            .filter(|e| e.kind == EventKind::AlertRaised)
            .map(|e| e.summary.clone())
            .collect()
    }

    fn run_scenario(store: &Store, name: &str) -> Vec<String> {
        let mut rules = RulesLayer::from_store(store);
        let mut titles = Vec::new();
        for packet in packets(name, 1_700_000_200_000).unwrap() {
            titles.extend(alert_titles(&engine::process_packet_with_rules(
                store, &packet, &mut rules,
            )));
        }
        titles
    }

    #[test]
    fn rogue_laptop_is_caught_three_ways() {
        let store = store_with_history();
        let titles = run_scenario(&store, "rogue-laptop");
        assert!(titles.iter().any(|t| t.contains("[new-device]")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("[write-from-non-hmi]")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("[write-outside-pattern]")), "{titles:?}");
    }

    #[test]
    fn office_reachdown_is_caught() {
        let store = store_with_history();
        let titles = run_scenario(&store, "office-reachdown");
        assert!(titles.iter().any(|t| t.contains("[it-to-controller]")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("[new-level-crossing]")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("[write-from-non-hmi]")), "{titles:?}");
    }

    #[test]
    fn recon_sweep_is_caught() {
        let store = store_with_history();
        let titles = run_scenario(&store, "recon-sweep");
        assert!(titles.iter().any(|t| t.contains("[new-device]")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("[rate-spike]")), "{titles:?}");
    }

    #[test]
    fn unknown_scenario_is_none() {
        assert!(packets("nonsense", 0).is_none());
        assert_eq!(catalog().len(), 4);
    }

    #[test]
    fn slow_recon_trips_only_the_anomaly_layer() {
        // The Phase 5 done-when: probing with no destructive action
        // raises an early warning, while no hard rule beyond the
        // informational new-device note fires.
        let store = store_with_history();
        // Train the anomaly layer on normal traffic first, as a
        // running monitor would be trained.
        {
            let mut rules = RulesLayer::from_store(&store);
            let mut anomaly = crate::detect::AnomalyLayer::from_store(&store);
            let mut source = SimulatedSource::new(1_700_000_100_000);
            for _ in 0..1300 {
                let packet = source.next_packet().unwrap();
                let events = engine::process_packet_full(&store, &packet, &mut rules, &mut anomaly);
                assert!(
                    !events.iter().any(|e| e.summary.contains("[early-warning]")),
                    "training traffic must not warn"
                );
            }
            assert!(!anomaly.learning, "layer trained after enough chunks");
        }
        // Fresh layers, as the app's scenario thread constructs them.
        let mut rules = RulesLayer::from_store(&store);
        let mut anomaly = crate::detect::AnomalyLayer::from_store(&store);
        let mut saw_warning = false;
        for packet in packets("slow-recon", 1_700_000_400_000).unwrap() {
            for event in engine::process_packet_full(&store, &packet, &mut rules, &mut anomaly) {
                if event.kind == EventKind::AlertRaised {
                    if event.summary.contains("[early-warning]") {
                        saw_warning = true;
                    } else {
                        assert!(
                            event.summary.contains("[new-device]"),
                            "only the new-device note may accompany the warning: {}",
                            event.summary
                        );
                    }
                }
            }
        }
        assert!(saw_warning, "the probing must raise an early warning");
    }
}
