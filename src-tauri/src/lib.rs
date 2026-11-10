//! Deadband desktop shell.
//!
//! This crate is intentionally thin: it owns the window, the Tauri
//! command bridge, and the simulation thread — nothing else. All
//! monitoring logic lives in `deadband-core` so it can be tested
//! without a UI and reused by a future headless sensor.

use deadband_core::model::{Event, EventKind};
use deadband_core::source::{SimulatedSource, TrafficSource};
use deadband_core::store::Store;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager};

/// Shared app state: the engine's store plus the simulation switch.
struct AppState {
    store: Arc<Mutex<Store>>,
    running: Arc<AtomicBool>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Engine status as sent to the frontend. Mirrors
/// `deadband_core::EngineStatus` in a serialisable form.
#[derive(Debug, Serialize)]
struct EngineStatusResponse {
    name: &'static str,
    version: &'static str,
    phase: &'static str,
    detection_layers: [&'static str; 3],
}

/// Returns core-engine status so the UI can prove the Rust ↔ UI bridge
/// works end to end.
#[tauri::command]
fn engine_status() -> EngineStatusResponse {
    let status = deadband_core::engine_status();
    EngineStatusResponse {
        name: status.name,
        version: status.version,
        phase: status.phase,
        detection_layers: status.detection_layers,
    }
}

/// One event as streamed to / loaded by the frontend log.
#[derive(Debug, Clone, Serialize)]
struct EventDto {
    id: Option<i64>,
    timestamp: i64,
    kind: &'static str,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    summary: String,
}

impl From<&Event> for EventDto {
    fn from(event: &Event) -> EventDto {
        EventDto {
            id: event.id,
            timestamp: event.timestamp,
            kind: match &event.kind {
                EventKind::PacketObserved => "packet",
                EventKind::DeviceDiscovered => "discovery",
                EventKind::ConnectionObserved => "connection",
                EventKind::ModbusCommand { is_write: true, .. } => "write",
                EventKind::ModbusCommand { .. } => "modbus",
                EventKind::AlertRaised => "alert",
            },
            src_ip: event.src_ip.map(|ip| ip.to_string()),
            dst_ip: event.dst_ip.map(|ip| ip.to_string()),
            summary: event.summary.clone(),
        }
    }
}

/// Simulation state for the UI's status line and counters.
#[derive(Debug, Serialize)]
struct SimulationStatus {
    running: bool,
    devices: i64,
    events: i64,
}

fn status_of(state: &AppState) -> SimulationStatus {
    let (devices, events) = state
        .store
        .lock()
        .map(|store| {
            (
                deadband_core::engine::stats(&store).devices,
                deadband_core::engine::stats(&store).events,
            )
        })
        .unwrap_or((0, 0));
    SimulationStatus { running: state.running.load(Ordering::Relaxed), devices, events }
}

/// Starts the simulated plant: registers its roster in the inventory,
/// then runs source → pipeline on a background thread, emitting each
/// stored event to the UI as `traffic`. Idempotent while running.
#[tauri::command]
fn start_simulation(app: tauri::AppHandle, state: tauri::State<AppState>) -> SimulationStatus {
    if state.running.swap(true, Ordering::Relaxed) {
        return status_of(&state);
    }
    let now_s = now_ms() / 1000;
    if let Ok(store) = state.store.lock() {
        for mut device in deadband_core::sim::roster() {
            device.first_seen = now_s;
            device.last_seen = now_s;
            let _ = store.add_device(&device);
        }
    }
    let store = Arc::clone(&state.store);
    let running = Arc::clone(&state.running);
    std::thread::spawn(move || {
        let mut source = SimulatedSource::new(now_ms());
        while running.load(Ordering::Relaxed) {
            for _ in 0..6 {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(packet) = source.next_packet() {
                    let events = match store.lock() {
                        Ok(store) => deadband_core::engine::process_packet(&store, &packet),
                        Err(_) => Vec::new(),
                    };
                    for event in &events {
                        let _ = app.emit("traffic", EventDto::from(event));
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
    });
    status_of(&state)
}

/// Stops the simulated plant. Stored events stay in the database.
#[tauri::command]
fn stop_simulation(state: tauri::State<AppState>) -> SimulationStatus {
    state.running.store(false, Ordering::Relaxed);
    status_of(&state)
}

/// Current simulation state and pipeline counters.
#[tauri::command]
fn simulation_status(state: tauri::State<AppState>) -> SimulationStatus {
    status_of(&state)
}

/// The most recent stored events (newest first) — the log's backlog
/// when the Events view opens.
#[tauri::command]
fn recent_events(state: tauri::State<AppState>, limit: i64) -> Vec<EventDto> {
    match state.store.lock() {
        Ok(store) => store
            .recent_events(limit.clamp(1, 500))
            .unwrap_or_default()
            .iter()
            .map(EventDto::from)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// One plant device for the UI's roster list.
#[derive(Debug, Serialize)]
struct DeviceDto {
    ip: String,
    level: Option<String>,
    role: String,
    label: Option<String>,
}

/// The simulated plant's roster (ground truth for the lab).
#[tauri::command]
fn plant_devices() -> Vec<DeviceDto> {
    deadband_core::sim::roster()
        .iter()
        .map(|device| DeviceDto {
            ip: device.ip.to_string(),
            level: device.level.map(|level| level.name().to_string()),
            role: device.role.as_tag().to_string(),
            label: device.label.clone(),
        })
        .collect()
}

/// Builds and runs the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Local-first storage: one SQLite file in the app's data
            // directory. If that is unavailable for any reason, fall
            // back to in-memory rather than refusing to start.
            let store = app
                .path()
                .app_data_dir()
                .and_then(|dir| {
                    std::fs::create_dir_all(&dir)?;
                    Ok(dir.join("deadband.db"))
                })
                .and_then(|path| Store::open(path).map_err(|e| std::io::Error::other(e.to_string())))
                .unwrap_or_else(|_| Store::open_in_memory().expect("in-memory store"));
            app.manage(AppState {
                store: Arc::new(Mutex::new(store)),
                running: Arc::new(AtomicBool::new(false)),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            engine_status,
            start_simulation,
            stop_simulation,
            simulation_status,
            recent_events,
            plant_devices
        ])
        .run(tauri::generate_context!())
        .expect("error while running Deadband");
}
