//! SQLite storage for the asset inventory, connections, and events.
//!
//! One local database file on the user's own machine — per the
//! local-first rule, nothing here syncs, phones home, or uploads.
//! In-memory databases are supported for tests and throwaway lab runs.
//!
//! Schema (Phase 0, deliberately small; later phases extend it):
//!
//! - `devices`     — one row per discovered device, keyed by IP.
//! - `connections` — one row per observed conversation, keyed by
//!   (src, dst, port, protocol).
//! - `events`      — the timestamped event log the UI and the baselines
//!   read from.

use crate::model::{Device, DeviceRole, Event, EventKind, PurdueLevel};
use rusqlite::{params, Connection};
use std::fmt;
use std::path::Path;

/// Storage failures (open / schema / query).
#[derive(Debug)]
pub struct StoreError(rusqlite::Error);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> StoreError {
        StoreError(err)
    }
}

/// Result alias for storage operations.
pub type Result<T> = std::result::Result<T, StoreError>;

/// The engine's SQLite store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Opens (creating if needed) the database at `path` and ensures
    /// the schema exists.
    pub fn open(path: impl AsRef<Path>) -> Result<Store> {
        let store = Store { conn: Connection::open(path)? };
        store.init_schema()?;
        Ok(store)
    }

    /// Opens a throwaway in-memory database (tests, lab demos).
    pub fn open_in_memory() -> Result<Store> {
        let store = Store { conn: Connection::open_in_memory()? };
        store.init_schema()?;
        Ok(store)
    }

    /// Creates the Phase 0 schema if it does not already exist.
    /// Idempotent — safe to run on every open.
    pub fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS devices (
                id         INTEGER PRIMARY KEY,
                ip         TEXT NOT NULL UNIQUE,
                mac        TEXT,
                level      TEXT,
                role       TEXT NOT NULL DEFAULT 'unknown',
                label      TEXT,
                first_seen INTEGER NOT NULL,
                last_seen  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connections (
                id           INTEGER PRIMARY KEY,
                src_ip       TEXT NOT NULL,
                dst_ip       TEXT NOT NULL,
                dst_port     INTEGER NOT NULL,
                protocol     TEXT NOT NULL DEFAULT 'unknown',
                first_seen   INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                packet_count INTEGER NOT NULL DEFAULT 0,
                byte_count   INTEGER NOT NULL DEFAULT 0,
                UNIQUE (src_ip, dst_ip, dst_port, protocol)
            );

            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                kind      TEXT NOT NULL,
                src_ip    TEXT,
                dst_ip    TEXT,
                summary   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
            CREATE INDEX IF NOT EXISTS idx_connections_pair ON connections (src_ip, dst_ip);
            ",
        )?;
        Ok(())
    }

    /// Inserts a device, or refreshes `last_seen` if its IP is already
    /// known. Returns the device's row id.
    pub fn add_device(&self, device: &Device) -> Result<i64> {
        self.conn.execute(
            "
            INSERT INTO devices (ip, mac, level, role, label, first_seen, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen
            ",
            params![
                device.ip.to_string(),
                device.mac,
                device.level.map(|level| level.label()),
                device.role.as_tag(),
                device.label,
                device.first_seen,
                device.last_seen,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// All stored devices, oldest first.
    pub fn list_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, mac, level, role, label, first_seen, last_seen
             FROM devices ORDER BY first_seen, id",
        )?;
        let rows = stmt.query_map([], |row| {
            let ip_text: String = row.get(1)?;
            let level_text: Option<String> = row.get(3)?;
            let role_text: String = row.get(4)?;
            Ok(Device {
                id: row.get(0)?,
                // IPs were written by us from IpAddr::to_string; a parse
                // failure would mean a corrupted/hand-edited database —
                // fall back to loopback rather than failing the listing.
                ip: ip_text.parse().unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1])),
                mac: row.get(2)?,
                level: level_text.as_deref().and_then(level_from_label),
                role: DeviceRole::from_tag(&role_text),
                label: row.get(5)?,
                first_seen: row.get(6)?,
                last_seen: row.get(7)?,
            })
        })?;
        let mut devices = Vec::new();
        for device in rows {
            devices.push(device?);
        }
        Ok(devices)
    }

    /// Writes a confirmed placement (level + role) for a device —
    /// the human-confirmed half of the placement inference loop.
    /// Returns false if the IP is unknown.
    pub fn update_device_placement(
        &self,
        ip: std::net::IpAddr,
        level: crate::model::PurdueLevel,
        role: crate::model::DeviceRole,
    ) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE devices SET level = ?2, role = ?3 WHERE ip = ?1",
            params![ip.to_string(), level.label(), role.as_tag()],
        )?;
        Ok(changed > 0)
    }

    /// Number of stored devices.
    pub fn device_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?)
    }

    /// Appends an event to the log. Returns its row id.
    pub fn record_event(&self, event: &Event) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO events (timestamp, kind, src_ip, dst_ip, summary)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.timestamp,
                event_kind_tag(&event.kind),
                event.src_ip.map(|ip| ip.to_string()),
                event.dst_ip.map(|ip| ip.to_string()),
                event.summary,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Number of stored events.
    pub fn event_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?)
    }

    /// True when a device with this IP is already in the inventory.
    pub fn device_exists(&self, ip: std::net::IpAddr) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM devices WHERE ip = ?1",
            params![ip.to_string()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Records one packet against a connection: inserts the row on
    /// first sight (returns `true`), otherwise bumps packet/byte
    /// counters and `last_seen` (returns `false`).
    pub fn record_connection(&self, conn: &crate::model::Connection) -> Result<bool> {
        let existing: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM connections
             WHERE src_ip = ?1 AND dst_ip = ?2 AND dst_port = ?3 AND protocol = ?4",
            params![
                conn.src_ip.to_string(),
                conn.dst_ip.to_string(),
                conn.dst_port,
                conn.protocol.as_tag(),
            ],
            |row| row.get(0),
        )?;
        if existing > 0 {
            self.conn.execute(
                "UPDATE connections
                 SET last_seen = ?1, packet_count = packet_count + ?2,
                     byte_count = byte_count + ?3
                 WHERE src_ip = ?4 AND dst_ip = ?5 AND dst_port = ?6 AND protocol = ?7",
                params![
                    conn.last_seen,
                    conn.packet_count as i64,
                    conn.byte_count as i64,
                    conn.src_ip.to_string(),
                    conn.dst_ip.to_string(),
                    conn.dst_port,
                    conn.protocol.as_tag(),
                ],
            )?;
            return Ok(false);
        }
        self.conn.execute(
            "INSERT INTO connections
             (src_ip, dst_ip, dst_port, protocol, first_seen, last_seen, packet_count, byte_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                conn.src_ip.to_string(),
                conn.dst_ip.to_string(),
                conn.dst_port,
                conn.protocol.as_tag(),
                conn.first_seen,
                conn.last_seen,
                conn.packet_count as i64,
                conn.byte_count as i64,
            ],
        )?;
        Ok(true)
    }

    /// All stored connections, busiest first (the map's conduits).
    pub fn list_connections(&self) -> Result<Vec<crate::model::Connection>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, src_ip, dst_ip, dst_port, protocol, first_seen, last_seen,
                    packet_count, byte_count
             FROM connections ORDER BY packet_count DESC, id",
        )?;
        let rows = stmt.query_map([], |row| {
            let src_text: String = row.get(1)?;
            let dst_text: String = row.get(2)?;
            let protocol_text: String = row.get(4)?;
            Ok(crate::model::Connection {
                id: row.get(0)?,
                src_ip: src_text.parse().unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1])),
                dst_ip: dst_text.parse().unwrap_or_else(|_| std::net::IpAddr::from([127, 0, 0, 1])),
                dst_port: row.get::<_, i64>(3)? as u16,
                protocol: crate::model::Protocol::from_tag(&protocol_text),
                first_seen: row.get(5)?,
                last_seen: row.get(6)?,
                packet_count: row.get::<_, i64>(7)? as u64,
                byte_count: row.get::<_, i64>(8)? as u64,
            })
        })?;
        let mut connections = Vec::new();
        for conn in rows {
            connections.push(conn?);
        }
        Ok(connections)
    }

    /// (writer, target) pairs that have ever written, reconstructed
    /// from stored Modbus command events — the rules layer's baseline
    /// of "who normally writes to whom" when it starts cold.
    pub fn write_pairs(&self) -> Result<Vec<(std::net::IpAddr, std::net::IpAddr)>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT src_ip, dst_ip FROM events
             WHERE kind = 'modbus_command' AND instr(summary, 'WRITE') > 0
               AND src_ip IS NOT NULL AND dst_ip IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |row| {
            let src: String = row.get(0)?;
            let dst: String = row.get(1)?;
            Ok((src, dst))
        })?;
        let mut pairs = Vec::new();
        for row in rows {
            let (src, dst) = row?;
            if let (Ok(src), Ok(dst)) = (src.parse(), dst.parse()) {
                pairs.push((src, dst));
            }
        }
        Ok(pairs)
    }

    /// The most recent alert event, if any (the analyst's subject).
    pub fn latest_alert(&self) -> Result<Option<Event>> {
        Ok(self
            .recent_events(500)?
            .into_iter()
            .find(|event| event.kind == EventKind::AlertRaised))
    }

    /// How many alert events have been stored (the Rules view counter).
    pub fn alert_count(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE kind = 'alert_raised'",
            [],
            |row| row.get(0),
        )?)
    }

    /// The most recent events, newest first (the UI's initial backlog).
    /// Kind tags are mapped back lossily — a stored Modbus event keeps
    /// its summary text, which carries the detail the log displays.
    pub fn recent_events(&self, limit: i64) -> Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, kind, src_ip, dst_ip, summary
             FROM events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let kind_text: String = row.get(2)?;
            let src_text: Option<String> = row.get(3)?;
            let dst_text: Option<String> = row.get(4)?;
            Ok(Event {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                kind: kind_from_tag(&kind_text),
                src_ip: src_text.as_deref().and_then(|text| text.parse().ok()),
                dst_ip: dst_text.as_deref().and_then(|text| text.parse().ok()),
                summary: row.get(5)?,
            })
        })?;
        let mut events = Vec::new();
        for event in rows {
            events.push(event?);
        }
        Ok(events)
    }
}

/// Inverse of [`event_kind_tag`], lossy for kinds that carry data
/// (their detail survives in the event summary text).
fn kind_from_tag(tag: &str) -> EventKind {
    match tag {
        "device_discovered" => EventKind::DeviceDiscovered,
        "connection_observed" => EventKind::ConnectionObserved,
        "modbus_command" => EventKind::ModbusCommand { function_code: 0, is_write: false },
        "alert_raised" => EventKind::AlertRaised,
        "analyst_note" => EventKind::AnalystNote,
        _ => EventKind::PacketObserved,
    }
}

/// Maps a stored level label ("3.5") back to a [`PurdueLevel`].
fn level_from_label(label: &str) -> Option<PurdueLevel> {
    PurdueLevel::ALL.iter().copied().find(|level| level.label() == label)
}

/// Stable storage tag for an [`EventKind`].
fn event_kind_tag(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::PacketObserved => "packet_observed",
        EventKind::DeviceDiscovered => "device_discovered",
        EventKind::ConnectionObserved => "connection_observed",
        EventKind::ModbusCommand { .. } => "modbus_command",
        EventKind::AlertRaised => "alert_raised",
        EventKind::AnalystNote => "analyst_note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn schema_init_is_idempotent() {
        let store = Store::open_in_memory().expect("open in-memory store");
        store.init_schema().expect("second init must also succeed");
        assert_eq!(store.device_count().unwrap(), 0);
        assert_eq!(store.event_count().unwrap(), 0);
    }

    #[test]
    fn devices_round_trip_with_level_and_role() {
        let store = Store::open_in_memory().unwrap();
        let mut plc = Device::new(ip(10, 0, 2, 15), 100);
        plc.level = Some(PurdueLevel::Control);
        plc.role = DeviceRole::Plc;
        plc.label = Some("Main PLC".to_string());

        store.add_device(&plc).unwrap();
        // Re-adding the same IP updates, never duplicates.
        store.add_device(&plc).unwrap();
        assert_eq!(store.device_count().unwrap(), 1);

        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].level, Some(PurdueLevel::Control));
        assert_eq!(devices[0].role, DeviceRole::Plc);
        assert_eq!(devices[0].label.as_deref(), Some("Main PLC"));
    }

    #[test]
    fn events_are_recorded_and_counted() {
        let store = Store::open_in_memory().unwrap();
        let mut event = Event::new(200, EventKind::DeviceDiscovered, "new device 10.0.2.15");
        event.src_ip = Some(ip(10, 0, 2, 15));
        store.record_event(&event).unwrap();
        store.record_event(&Event::new(201, EventKind::PacketObserved, "poll")).unwrap();
        assert_eq!(store.event_count().unwrap(), 2);
    }

    #[test]
    fn connections_upsert_and_count() {
        use crate::model::{Connection, Protocol};
        let store = Store::open_in_memory().unwrap();
        let conn = Connection {
            id: None,
            src_ip: ip(10, 0, 2, 10),
            dst_ip: ip(10, 0, 1, 11),
            dst_port: 502,
            protocol: Protocol::ModbusTcp,
            first_seen: 10,
            last_seen: 10,
            packet_count: 1,
            byte_count: 66,
        };
        assert!(store.record_connection(&conn).unwrap(), "first sight inserts");
        assert!(!store.record_connection(&conn).unwrap(), "second sight updates");
        let listed = store.list_connections().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].packet_count, 2);
        assert_eq!(listed[0].protocol, Protocol::ModbusTcp);
        let count: i64 = store
            .conn
            .query_row("SELECT packet_count FROM connections", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn recent_events_come_back_newest_first() {
        let store = Store::open_in_memory().unwrap();
        assert!(!store.device_exists(ip(10, 0, 1, 11)).unwrap());
        store.record_event(&Event::new(1, EventKind::PacketObserved, "first")).unwrap();
        store.record_event(&Event::new(2, EventKind::PacketObserved, "second")).unwrap();
        let recent = store.recent_events(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].summary, "second");
        assert_eq!(recent[1].summary, "first");
    }
}
