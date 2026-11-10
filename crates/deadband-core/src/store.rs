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
}
