//! Placement inference: guess a device's Purdue level and role from
//! its observed behavior, so commissioning is "confirm or correct"
//! instead of "name everything from a blank map".
//!
//! The signals are all conversational, readable off the connection
//! table the pipeline already maintains:
//!
//!   * Answers Modbus polls, never starts them      -> controller (L1)
//!   * Polls controllers AND serves data upward     -> historian (L3)
//!   * Polls controllers at volume, all day         -> operator HMI (L2)
//!   * Writes to controllers but barely polls       -> engineering (L2)
//!   * Only ever a client of data services          -> office PC (L4)
//!
//! Every guess carries a confidence and the reasons behind it; a
//! human confirms before anything is written back (see
//! `Store::update_device_placement`). Devices with too little
//! observed behavior get NO guess rather than a coin flip.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::model::{DeviceRole, PurdueLevel};
use crate::store::{Result, Store};

const MODBUS_PORT: u16 = 502;
const DATA_PORTS: [u16; 3] = [80, 443, 8080];
/// Below this many Modbus-client packets, a writing device looks
/// like an engineering station (occasional, deliberate) rather than
/// an HMI (relentless polling plus the odd setpoint write).
const ENGINEERING_PACKET_CEILING: u64 = 30;

#[derive(Debug, Clone, PartialEq)]
pub struct Placement {
    pub role: DeviceRole,
    pub level: PurdueLevel,
    /// 0–100. Below ~60 the UI should present the guess as tentative.
    pub confidence: u8,
    pub reasons: Vec<String>,
}

struct Signals {
    modbus_servers_polled: BTreeSet<IpAddr>,
    modbus_client_packets: u64,
    modbus_pollers: BTreeSet<IpAddr>,
    serves_data_to: BTreeSet<IpAddr>,
    data_services_used: BTreeSet<IpAddr>,
    writes_to: BTreeSet<IpAddr>,
}

fn signals(store: &Store, ip: IpAddr) -> Result<Signals> {
    let mut s = Signals {
        modbus_servers_polled: BTreeSet::new(),
        modbus_client_packets: 0,
        modbus_pollers: BTreeSet::new(),
        serves_data_to: BTreeSet::new(),
        data_services_used: BTreeSet::new(),
        writes_to: BTreeSet::new(),
    };
    for conn in store.list_connections()? {
        if conn.src_ip == ip && conn.dst_port == MODBUS_PORT {
            s.modbus_servers_polled.insert(conn.dst_ip);
            s.modbus_client_packets += conn.packet_count;
        }
        if conn.dst_ip == ip && conn.dst_port == MODBUS_PORT {
            s.modbus_pollers.insert(conn.src_ip);
        }
        if conn.dst_ip == ip && DATA_PORTS.contains(&conn.dst_port) {
            s.serves_data_to.insert(conn.src_ip);
        }
        if conn.src_ip == ip && DATA_PORTS.contains(&conn.dst_port) {
            s.data_services_used.insert(conn.dst_ip);
        }
    }
    for (src, dst) in store.write_pairs()? {
        if src == ip {
            s.writes_to.insert(dst);
        }
    }
    Ok(s)
}

/// The inference for one device, if its behavior supports one.
pub fn infer(store: &Store, ip: IpAddr) -> Result<Option<Placement>> {
    let s = signals(store, ip)?;

    // Answers Modbus polls: a controller. The strongest signal there
    // is — Modbus servers at Level 1 are what everything else orbits.
    if !s.modbus_pollers.is_empty() {
        return Ok(Some(Placement {
            role: DeviceRole::Plc,
            level: PurdueLevel::Control,
            confidence: 90,
            reasons: vec![format!(
                "answers Modbus polls from {} device(s); controllers are polled, they do not poll",
                s.modbus_pollers.len()
            )],
        }));
    }

    if !s.modbus_servers_polled.is_empty() {
        // Gathers from controllers AND serves data upward: historian.
        if !s.serves_data_to.is_empty() {
            return Ok(Some(Placement {
                role: DeviceRole::Historian,
                level: PurdueLevel::Operations,
                confidence: 85,
                reasons: vec![
                    format!(
                        "polls {} controller(s) for data",
                        s.modbus_servers_polled.len()
                    ),
                    format!(
                        "serves data onward to {} client(s) — the historian's two-sided job",
                        s.serves_data_to.len()
                    ),
                ],
            }));
        }
        // Writes prominently, polls barely: engineering station.
        if !s.writes_to.is_empty() && s.modbus_client_packets < ENGINEERING_PACKET_CEILING {
            return Ok(Some(Placement {
                role: DeviceRole::EngineeringStation,
                level: PurdueLevel::Supervisory,
                confidence: 60,
                reasons: vec![format!(
                    "writes to {} controller(s) but polls very little ({} packets) — programming-station shape, not an operator screen",
                    s.writes_to.len(),
                    s.modbus_client_packets
                )],
            }));
        }
        // Relentless poller of controllers: the operator's screen.
        return Ok(Some(Placement {
            role: DeviceRole::Hmi,
            level: PurdueLevel::Supervisory,
            confidence: 80,
            reasons: vec![format!(
                "polls {} controller(s) continuously ({} packets) — an operator screen watching the process",
                s.modbus_servers_polled.len(),
                s.modbus_client_packets
            )],
        }));
    }

    // No OT behavior at all, just data services.
    if s.modbus_servers_polled.is_empty() && s.modbus_pollers.is_empty() {
        if !s.data_services_used.is_empty() && s.serves_data_to.is_empty() {
            return Ok(Some(Placement {
                role: DeviceRole::OfficePc,
                level: PurdueLevel::Enterprise,
                confidence: 75,
                reasons: vec![
                    "only ever a client of data services; no industrial protocol seen".to_string(),
                ],
            }));
        }
        if !s.serves_data_to.is_empty() {
            return Ok(Some(Placement {
                role: DeviceRole::Server,
                level: PurdueLevel::Operations,
                confidence: 55,
                reasons: vec![
                    "serves data to other devices but speaks no industrial protocol itself"
                        .to_string(),
                ],
            }));
        }
    }

    Ok(None)
}

/// Suggestions for every stored device that is still unplaced.
pub fn suggestions(store: &Store) -> Result<Vec<(IpAddr, Placement)>> {
    let mut out = Vec::new();
    for device in store.list_devices()? {
        if device.level.is_none() {
            if let Some(p) = infer(store, device.ip)? {
                out.push((device.ip, p));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::process_packet;
    use crate::{sample, sim};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn feed(store: &mut Store, packets: Vec<crate::source::Packet>) {
        for p in packets {
            process_packet(store, &p);
        }
    }

    fn sim_traffic(count: usize) -> Vec<crate::source::Packet> {
        let mut plant = sim::Plant::new();
        (0..count).map(|_| plant.next_packet(0)).collect()
    }

    fn pd_ip(d: sim::PlantDevice) -> IpAddr {
        IpAddr::from(d.ip)
    }

    #[test]
    fn sim_plant_is_placed_correctly() {
        let mut store = Store::open_in_memory().unwrap();
        feed(&mut store, sim_traffic(400));
        let plc = infer(&store, pd_ip(sim::PLC1)).unwrap().expect("plc placed");
        assert_eq!(plc.role, DeviceRole::Plc);
        assert_eq!(plc.level, PurdueLevel::Control);
        assert!(plc.confidence >= 80, "plc confidence {}", plc.confidence);
        let hmi = infer(&store, pd_ip(sim::HMI)).unwrap().expect("hmi placed");
        assert_eq!(hmi.role, DeviceRole::Hmi, "hmi reasons: {:?}", hmi.reasons);
        assert_eq!(hmi.level, PurdueLevel::Supervisory);
        let hist = infer(&store, pd_ip(sim::HISTORIAN)).unwrap().expect("historian placed");
        assert_eq!(hist.role, DeviceRole::Historian, "hist reasons: {:?}", hist.reasons);
        assert_eq!(hist.level, PurdueLevel::Operations);
        let office = infer(&store, pd_ip(sim::OFFICE_PC)).unwrap().expect("office placed");
        assert_eq!(office.role, DeviceRole::OfficePc);
        assert_eq!(office.level, PurdueLevel::Enterprise);
    }

    #[test]
    fn sample_capture_foreigners_are_placed() {
        let mut store = Store::open_in_memory().unwrap();
        feed(&mut store, sample::sample_packets());
        let plc = infer(&store, ip("192.168.50.41")).unwrap().expect("sample plc");
        assert_eq!(plc.role, DeviceRole::Plc);
        assert_eq!(plc.level, PurdueLevel::Control);
        let hmi = infer(&store, ip("192.168.50.30")).unwrap().expect("sample hmi");
        assert_eq!(hmi.role, DeviceRole::Hmi, "sample hmi reasons: {:?}", hmi.reasons);
        let hist = infer(&store, ip("192.168.50.20")).unwrap().expect("sample historian");
        assert_eq!(hist.role, DeviceRole::Historian, "sample hist reasons: {:?}", hist.reasons);
        // The mystery laptop: reads a controller a few times and writes
        // once — if guessed at all, it must be tentative, never sure.
        if let Some(laptop) = infer(&store, ip("192.168.50.77")).unwrap() {
            assert!(laptop.confidence < 80, "laptop overconfident: {:?}", laptop);
        }
        // All six devices appear in the suggestion list (each had
        // enough behavior to grade; the office PC included).
        let sugg = suggestions(&store).unwrap();
        assert!(sugg.len() >= 4, "only {} suggestions", sugg.len());
    }

    #[test]
    fn silent_device_gets_no_guess() {
        let store = Store::open_in_memory().unwrap();
        assert!(infer(&store, ip("10.9.9.9")).unwrap().is_none());
    }
}
