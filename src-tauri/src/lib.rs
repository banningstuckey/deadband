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

/// Shared app state: the engine's store plus the feed switches.
struct AppState {
    store: Arc<Mutex<Store>>,
    running: Arc<AtomicBool>,
    replay_running: Arc<AtomicBool>,
    replay_info: Arc<Mutex<ReplayInfo>>,
}

/// Bookkeeping for the capture replay, for the UI's status line.
#[derive(Debug, Default, Clone)]
struct ReplayInfo {
    label: Option<String>,
    total: usize,
    done: usize,
    finished: bool,
    message: Option<String>,
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
    // One live feed at a time: starting the plant stops any replay.
    state.replay_running.store(false, Ordering::Relaxed);
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
        let mut rules = match store.lock() {
            Ok(store) => deadband_core::detect::RulesLayer::from_store(&store),
            Err(_) => deadband_core::detect::RulesLayer::new(),
        };
        while running.load(Ordering::Relaxed) {
            for _ in 0..6 {
                if !running.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(packet) = source.next_packet() {
                    let events = match store.lock() {
                        Ok(store) => deadband_core::engine::process_packet_with_rules(
                            &store, &packet, &mut rules,
                        ),
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

/// Replay state for the UI's status line.
#[derive(Debug, Serialize)]
struct ReplayStatus {
    running: bool,
    label: Option<String>,
    done: usize,
    total: usize,
    finished: bool,
    message: Option<String>,
}

fn replay_status_of(state: &AppState) -> ReplayStatus {
    let info = state.replay_info.lock().map(|info| info.clone()).unwrap_or_default();
    ReplayStatus {
        running: state.replay_running.load(Ordering::Relaxed),
        label: info.label,
        done: info.done,
        total: info.total,
        finished: info.finished,
        message: info.message,
    }
}

/// Starts a capture replay: a `.pcap` file from disk when `path` is
/// given, otherwise the bundled sample capture. Packets flow through
/// the same pipeline as the simulated plant; timestamps are rebased
/// so the capture plays as if it were happening now, paced at the
/// capture's own rhythm divided by `speed`.
#[tauri::command]
fn start_replay(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    path: Option<String>,
    speed: Option<f64>,
) -> ReplayStatus {
    if state.replay_running.swap(true, Ordering::Relaxed) {
        return replay_status_of(&state);
    }
    let fail = |state: &AppState, message: String| {
        state.replay_running.store(false, Ordering::Relaxed);
        if let Ok(mut info) = state.replay_info.lock() {
            *info = ReplayInfo { message: Some(message), ..ReplayInfo::default() };
        }
        replay_status_of(state)
    };
    let (label, packets) = match path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        Some(path) => {
            let bytes = match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(e) => return fail(&state, format!("Could not read {path}: {e}")),
            };
            match deadband_core::pcap::read_pcap(&bytes) {
                Ok(packets) => (path.to_string(), packets),
                Err(e) => return fail(&state, format!("{path}: {e}")),
            }
        }
        None => ("bundled sample capture".to_string(), deadband_core::sample::sample_packets()),
    };
    if packets.is_empty() {
        return fail(&state, format!("{label}: no packets in capture"));
    }
    // One live feed at a time: replaying stops the simulated plant.
    state.running.store(false, Ordering::Relaxed);
    let speed = speed.unwrap_or(1.0);
    let speed = if speed.is_finite() { speed.clamp(0.25, 100.0) } else { 1.0 };
    let shift = now_ms() - packets[0].timestamp_ms;
    let total = packets.len();
    if let Ok(mut info) = state.replay_info.lock() {
        *info = ReplayInfo {
            label: Some(label),
            total,
            done: 0,
            finished: false,
            message: None,
        };
    }
    let store = Arc::clone(&state.store);
    let running = Arc::clone(&state.replay_running);
    let info_handle = Arc::clone(&state.replay_info);
    std::thread::spawn(move || {
        let mut rules = match store.lock() {
            Ok(store) => deadband_core::detect::RulesLayer::from_store(&store),
            Err(_) => deadband_core::detect::RulesLayer::new(),
        };
        let mut previous_ts: Option<i64> = None;
        for (index, packet) in packets.iter().enumerate() {
            if !running.load(Ordering::Relaxed) {
                return;
            }
            if let Some(previous) = previous_ts {
                let delta_ms = (packet.timestamp_ms - previous).max(0) as f64 / speed;
                let sleep_ms = delta_ms.min(2_500.0) as u64;
                if sleep_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                }
            }
            previous_ts = Some(packet.timestamp_ms);
            let shifted = deadband_core::source::Packet {
                timestamp_ms: packet.timestamp_ms + shift,
                data: packet.data.clone(),
            };
            let events = match store.lock() {
                Ok(store) => deadband_core::engine::process_packet_with_rules(
                    &store, &shifted, &mut rules,
                ),
                Err(_) => Vec::new(),
            };
            for event in &events {
                let _ = app.emit("traffic", EventDto::from(event));
            }
            if let Ok(mut info) = info_handle.lock() {
                info.done = index + 1;
            }
        }
        if let Ok(mut info) = info_handle.lock() {
            info.finished = true;
        }
        running.store(false, Ordering::Relaxed);
    });
    replay_status_of(&state)
}

/// Stops the capture replay. Stored events stay in the database.
#[tauri::command]
fn stop_replay(state: tauri::State<AppState>) -> ReplayStatus {
    state.replay_running.store(false, Ordering::Relaxed);
    replay_status_of(&state)
}

/// Current replay state (the UI polls this alongside the sim status).
#[tauri::command]
fn replay_status(state: tauri::State<AppState>) -> ReplayStatus {
    replay_status_of(&state)
}

/// One rule, for the Rules view.
#[derive(Debug, Serialize)]
struct RuleDto {
    id: &'static str,
    name: &'static str,
    description: &'static str,
}

/// One attack scenario, for the Rules view buttons.
#[derive(Debug, Serialize)]
struct ScenarioDto {
    id: &'static str,
    title: &'static str,
    blurb: &'static str,
}

/// Everything the Rules view shows.
#[derive(Debug, Serialize)]
struct RulesStatus {
    alerts_total: i64,
    events_total: i64,
    baseline_ready: bool,
    rules: Vec<RuleDto>,
    scenarios: Vec<ScenarioDto>,
}

/// The rules catalog, scenario catalog, and alert counters.
#[tauri::command]
fn rules_status(state: tauri::State<AppState>) -> RulesStatus {
    let (alerts_total, events_total) = state
        .store
        .lock()
        .map(|store| {
            (
                store.alert_count().unwrap_or(0),
                deadband_core::engine::stats(&store).events,
            )
        })
        .unwrap_or((0, 0));
    RulesStatus {
        alerts_total,
        events_total,
        baseline_ready: events_total >= deadband_core::detect::BASELINE_EVENTS,
        rules: deadband_core::detect::rule_catalog()
            .iter()
            .map(|r| RuleDto { id: r.id, name: r.name, description: r.description })
            .collect(),
        scenarios: deadband_core::scenarios::catalog()
            .iter()
            .map(|s| ScenarioDto { id: s.id, title: s.title, blurb: s.blurb })
            .collect(),
    }
}

/// Runs a lab attack scenario through the pipeline with the rules
/// armed. Returns false for an unknown scenario id. The scenario's
/// packets are generated frames for the lab only — nothing is ever
/// transmitted anywhere (passive-only rule).
#[tauri::command]
fn run_scenario(app: tauri::AppHandle, state: tauri::State<AppState>, name: String) -> bool {
    let Some(packets) = deadband_core::scenarios::packets(&name, now_ms()) else {
        return false;
    };
    let store = Arc::clone(&state.store);
    std::thread::spawn(move || {
        let mut rules = match store.lock() {
            Ok(store) => deadband_core::detect::RulesLayer::from_store(&store),
            Err(_) => deadband_core::detect::RulesLayer::new(),
        };
        let mut previous_ts: Option<i64> = None;
        for packet in &packets {
            if let Some(previous) = previous_ts {
                let delta = ((packet.timestamp_ms - previous).max(0) / 4).min(250) as u64;
                if delta > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(delta));
                }
            }
            previous_ts = Some(packet.timestamp_ms);
            let events = match store.lock() {
                Ok(store) => deadband_core::engine::process_packet_with_rules(
                    &store, packet, &mut rules,
                ),
                Err(_) => Vec::new(),
            };
            for event in &events {
                let _ = app.emit("traffic", EventDto::from(event));
            }
        }
    });
    true
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

/// One device for the Purdue map, from the live inventory.
#[derive(Debug, Serialize)]
struct MapDeviceDto {
    ip: String,
    label: Option<String>,
    role: String,
    level_label: Option<String>,
    level_name: Option<String>,
    first_seen: i64,
    last_seen: i64,
}

/// One conduit for the Purdue map, from the connection table.
#[derive(Debug, Serialize)]
struct MapConnectionDto {
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
    protocol: String,
    packet_count: u64,
}

/// Everything the map draws: inventory + conduits in one call.
#[derive(Debug, Serialize)]
struct NetworkSnapshot {
    devices: Vec<MapDeviceDto>,
    connections: Vec<MapConnectionDto>,
}

/// The live network snapshot behind the Purdue map.
#[tauri::command]
fn network_snapshot(state: tauri::State<AppState>) -> NetworkSnapshot {
    let empty = NetworkSnapshot { devices: Vec::new(), connections: Vec::new() };
    let Ok(store) = state.store.lock() else { return empty };
    let devices = store
        .list_devices()
        .unwrap_or_default()
        .iter()
        .map(|d| MapDeviceDto {
            ip: d.ip.to_string(),
            label: d.label.clone(),
            role: d.role.as_tag().to_string(),
            level_label: d.level.map(|l| l.label().to_string()),
            level_name: d.level.map(|l| l.name().to_string()),
            first_seen: d.first_seen,
            last_seen: d.last_seen,
        })
        .collect();
    let connections = store
        .list_connections()
        .unwrap_or_default()
        .iter()
        .map(|c| MapConnectionDto {
            src_ip: c.src_ip.to_string(),
            dst_ip: c.dst_ip.to_string(),
            dst_port: c.dst_port,
            protocol: c.protocol.as_tag().to_string(),
            packet_count: c.packet_count,
        })
        .collect();
    NetworkSnapshot { devices, connections }
}

/// Builds and runs the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            // Local-first storage: one SQLite file in the app's data
            // directory. If that is unavailable for any reason, fall
            // back to in-memory rather than refusing to start.
            let file_store = (|| -> Option<Store> {
                let dir = app.path().app_data_dir().ok()?;
                std::fs::create_dir_all(&dir).ok()?;
                Store::open(dir.join("deadband.db")).ok()
            })();
            let store = file_store
                .unwrap_or_else(|| Store::open_in_memory().expect("in-memory store"));
            app.manage(AppState {
                store: Arc::new(Mutex::new(store)),
                running: Arc::new(AtomicBool::new(false)),
                replay_running: Arc::new(AtomicBool::new(false)),
                replay_info: Arc::new(Mutex::new(ReplayInfo::default())),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            engine_status,
            start_simulation,
            stop_simulation,
            simulation_status,
            recent_events,
            plant_devices,
            network_snapshot,
            start_replay,
            stop_replay,
            replay_status,
            rules_status,
            run_scenario
        ])
        .run(tauri::generate_context!())
        .expect("error while running Deadband");
}
