//! Core data types shared by every stage of the pipeline: the Purdue
//! levels a device can sit on, the devices and connections discovered
//! passively from traffic, and the events everything else works with.
//!
//! Types here are plain data — no I/O, no behaviour beyond naming and
//! ordering — so parsers, storage, detection, and tests all speak the
//! same language.

use std::fmt;
use std::net::IpAddr;

/// A level of the Purdue Model (ISA-95 / PERA), top (internet) to bottom
/// (physical process). The IT/OT boundary — and the Level 3.5 DMZ that
/// guards it — is where most of Deadband's attention lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PurdueLevel {
    /// Level 5 — internet / external services. Attackers start here.
    Internet,
    /// Level 4 — enterprise IT: email, office laptops, business systems.
    Enterprise,
    /// Level 3.5 — the IT/OT DMZ: historian mirrors, jump hosts, patch
    /// relays. Nothing should pass straight through this zone.
    Dmz,
    /// Level 3 — site operations: historians, application servers,
    /// operations management.
    Operations,
    /// Level 2 — supervisory control: HMIs, SCADA servers, engineering
    /// workstations.
    Supervisory,
    /// Level 1 — basic control: PLCs, RTUs, controllers that directly
    /// drive the process.
    Control,
    /// Level 0 — the physical process: sensors, actuators, motors,
    /// protective relays.
    Physical,
}

impl PurdueLevel {
    /// All levels, top to bottom — handy for drawing the map and for
    /// iterating in order.
    pub const ALL: [PurdueLevel; 7] = [
        PurdueLevel::Internet,
        PurdueLevel::Enterprise,
        PurdueLevel::Dmz,
        PurdueLevel::Operations,
        PurdueLevel::Supervisory,
        PurdueLevel::Control,
        PurdueLevel::Physical,
    ];

    /// Numeric label as printed on Purdue diagrams ("5", "3.5", "0", …).
    pub fn label(&self) -> &'static str {
        match self {
            PurdueLevel::Internet => "5",
            PurdueLevel::Enterprise => "4",
            PurdueLevel::Dmz => "3.5",
            PurdueLevel::Operations => "3",
            PurdueLevel::Supervisory => "2",
            PurdueLevel::Control => "1",
            PurdueLevel::Physical => "0",
        }
    }

    /// Human-readable name ("Level 3.5 — IT/OT DMZ").
    pub fn name(&self) -> &'static str {
        match self {
            PurdueLevel::Internet => "Level 5 — Internet",
            PurdueLevel::Enterprise => "Level 4 — Enterprise IT",
            PurdueLevel::Dmz => "Level 3.5 — IT/OT DMZ",
            PurdueLevel::Operations => "Level 3 — Operations",
            PurdueLevel::Supervisory => "Level 2 — Supervisory Control",
            PurdueLevel::Control => "Level 1 — Basic Control",
            PurdueLevel::Physical => "Level 0 — Physical Process",
        }
    }

    /// True for levels on the control side of the DMZ (Level 3 and below)
    /// — the zone an attacker must never reach.
    pub fn is_ot(&self) -> bool {
        matches!(
            self,
            PurdueLevel::Operations
                | PurdueLevel::Supervisory
                | PurdueLevel::Control
                | PurdueLevel::Physical
        )
    }
}

impl fmt::Display for PurdueLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// What a device appears to *do*, inferred passively from its traffic
/// (Phase 3 refines these guesses; Phase 0 only defines the vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceRole {
    /// Not enough traffic seen yet to guess.
    Unknown,
    /// Ordinary office/IT workstation (Level 4).
    OfficePc,
    /// Server (IT or OT side, per its level).
    Server,
    /// Data historian — collects and stores process history (Level 3,
    /// mirrored into the DMZ).
    Historian,
    /// Human-machine interface — the operator's screen (Level 2).
    Hmi,
    /// Engineering workstation — programs the controllers (Level 2).
    /// The highest-value target in most real OT intrusions.
    EngineeringStation,
    /// Programmable logic controller (Level 1).
    Plc,
    /// Remote terminal unit (Level 1).
    Rtu,
    /// Sensor / field device (Level 0).
    Sensor,
    /// Protective relay (Level 0/1).
    ProtectiveRelay,
}

impl DeviceRole {
    /// Stable lowercase tag used in storage. Keep in sync with
    /// [`DeviceRole::from_tag`].
    pub fn as_tag(&self) -> &'static str {
        match self {
            DeviceRole::Unknown => "unknown",
            DeviceRole::OfficePc => "office_pc",
            DeviceRole::Server => "server",
            DeviceRole::Historian => "historian",
            DeviceRole::Hmi => "hmi",
            DeviceRole::EngineeringStation => "engineering_station",
            DeviceRole::Plc => "plc",
            DeviceRole::Rtu => "rtu",
            DeviceRole::Sensor => "sensor",
            DeviceRole::ProtectiveRelay => "protective_relay",
        }
    }

    /// Inverse of [`DeviceRole::as_tag`]; unknown tags map to
    /// [`DeviceRole::Unknown`] rather than failing.
    pub fn from_tag(tag: &str) -> DeviceRole {
        match tag {
            "office_pc" => DeviceRole::OfficePc,
            "server" => DeviceRole::Server,
            "historian" => DeviceRole::Historian,
            "hmi" => DeviceRole::Hmi,
            "engineering_station" => DeviceRole::EngineeringStation,
            "plc" => DeviceRole::Plc,
            "rtu" => DeviceRole::Rtu,
            "sensor" => DeviceRole::Sensor,
            "protective_relay" => DeviceRole::ProtectiveRelay,
            _ => DeviceRole::Unknown,
        }
    }
}

/// A single device discovered on the monitored network.
#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    /// Database row id; `None` until the device has been stored.
    pub id: Option<i64>,
    /// Primary IP address the device was observed at.
    pub ip: IpAddr,
    /// MAC address, when the traffic source provides one.
    pub mac: Option<String>,
    /// Purdue level the device is believed to sit on. Users can correct
    /// this by hand; detection rules treat it as ground truth.
    pub level: Option<PurdueLevel>,
    /// Best-guess role, inferred from traffic.
    pub role: DeviceRole,
    /// Optional user-facing label ("Main PLC", "North HMI", …).
    pub label: Option<String>,
    /// First observation, Unix seconds.
    pub first_seen: i64,
    /// Most recent observation, Unix seconds.
    pub last_seen: i64,
}

impl Device {
    /// A freshly discovered device with no storage id and no level yet.
    pub fn new(ip: IpAddr, now: i64) -> Device {
        Device {
            id: None,
            ip,
            mac: None,
            level: None,
            role: DeviceRole::Unknown,
            label: None,
            first_seen: now,
            last_seen: now,
        }
    }
}

/// Transport / application protocol of a [`Connection`], as far as the
/// parser could identify it. Phase 1 implements IP/TCP/UDP basics and
/// Modbus/TCP; more protocols are later plugins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Not yet classified.
    Unknown,
    /// Plain TCP that matched no known application protocol.
    Tcp,
    /// Plain UDP that matched no known application protocol.
    Udp,
    /// Modbus/TCP (normally port 502) — the v1 industrial protocol.
    ModbusTcp,
    /// DNP3 (electric utilities) — recognised vocabulary, not parsed in v1.
    Dnp3,
}

impl Protocol {
    /// Stable lowercase tag used in storage.
    pub fn as_tag(&self) -> &'static str {
        match self {
            Protocol::Unknown => "unknown",
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::ModbusTcp => "modbus_tcp",
            Protocol::Dnp3 => "dnp3",
        }
    }

    /// Inverse of [`Protocol::as_tag`].
    pub fn from_tag(tag: &str) -> Protocol {
        match tag {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "modbus_tcp" => Protocol::ModbusTcp,
            "dnp3" => Protocol::Dnp3,
            _ => Protocol::Unknown,
        }
    }
}

/// An observed conversation between two devices: who talks to whom, how,
/// and how much. Connections are what get drawn as lines on the Purdue
/// map and what the baseline (Phase 5) learns as "normal".
#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    /// Database row id; `None` until stored.
    pub id: Option<i64>,
    /// Initiator / talker.
    pub src_ip: IpAddr,
    /// Listener / target.
    pub dst_ip: IpAddr,
    /// Destination (service) port.
    pub dst_port: u16,
    /// Identified protocol.
    pub protocol: Protocol,
    /// First observation, Unix seconds.
    pub first_seen: i64,
    /// Most recent observation, Unix seconds.
    pub last_seen: i64,
    /// Total packets observed in this conversation.
    pub packet_count: u64,
    /// Total bytes observed in this conversation.
    pub byte_count: u64,
}

/// The kind of an [`Event`] — the engine's unit of "something happened".
#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    /// A packet was observed and parsed.
    PacketObserved,
    /// A device was seen for the first time.
    DeviceDiscovered,
    /// A connection was seen for the first time.
    ConnectionObserved,
    /// A Modbus command was decoded (function code; read vs write is the
    /// distinction detection cares most about).
    ModbusCommand {
        /// Modbus function code (e.g. 3 = read holding registers,
        /// 6/16 = write registers).
        function_code: u8,
        /// True for function codes that change state on the target.
        is_write: bool,
    },
    /// A detection layer raised an alert (detail lives in the alert).
    AlertRaised,
}

/// One timestamped observation flowing through the pipeline. Events are
/// stored, counted into baselines, and shown in the UI's event log.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Database row id; `None` until stored.
    pub id: Option<i64>,
    /// When it happened, Unix seconds.
    pub timestamp: i64,
    /// What happened.
    pub kind: EventKind,
    /// Source device IP, when applicable.
    pub src_ip: Option<IpAddr>,
    /// Destination device IP, when applicable.
    pub dst_ip: Option<IpAddr>,
    /// Short human-readable summary for the event log
    /// (e.g. "HMI polled PLC (read holding registers)").
    pub summary: String,
}

impl Event {
    /// Convenience constructor for an unstored event.
    pub fn new(timestamp: i64, kind: EventKind, summary: impl Into<String>) -> Event {
        Event {
            id: None,
            timestamp,
            kind,
            src_ip: None,
            dst_ip: None,
            summary: summary.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn levels_are_ordered_top_to_bottom() {
        assert!(PurdueLevel::Internet < PurdueLevel::Enterprise);
        assert!(PurdueLevel::Dmz < PurdueLevel::Operations);
        assert!(PurdueLevel::Control < PurdueLevel::Physical);
        assert_eq!(PurdueLevel::ALL.len(), 7);
    }

    #[test]
    fn dmz_is_not_ot_but_level_3_is() {
        assert!(!PurdueLevel::Dmz.is_ot());
        assert!(PurdueLevel::Operations.is_ot());
        assert!(PurdueLevel::Control.is_ot());
    }

    #[test]
    fn role_and_protocol_tags_round_trip() {
        for role in [
            DeviceRole::Unknown,
            DeviceRole::Hmi,
            DeviceRole::Plc,
            DeviceRole::EngineeringStation,
        ] {
            assert_eq!(DeviceRole::from_tag(role.as_tag()), role);
        }
        assert_eq!(Protocol::from_tag(Protocol::ModbusTcp.as_tag()), Protocol::ModbusTcp);
        assert_eq!(DeviceRole::from_tag("nonsense"), DeviceRole::Unknown);
    }

    #[test]
    fn new_device_starts_unclassified() {
        let device = Device::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 1_700_000_000);
        assert_eq!(device.role, DeviceRole::Unknown);
        assert_eq!(device.level, None);
        assert_eq!(device.first_seen, device.last_seen);
    }
}
