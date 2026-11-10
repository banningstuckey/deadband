//! Deadband desktop shell.
//!
//! This crate is intentionally thin: it owns the window, the Tauri
//! command bridge, and nothing else. All monitoring logic lives in
//! `deadband-core` so it can be tested without a UI and reused by a
//! future headless sensor.

use serde::Serialize;

/// Engine status as sent to the frontend. Mirrors
/// `deadband_core::EngineStatus` in a serialisable form.
#[derive(Debug, Serialize)]
struct EngineStatusResponse {
    name: &'static str,
    version: &'static str,
    phase: &'static str,
    detection_layers: [&'static str; 3],
}

/// Returns core-engine status so the placeholder UI can prove the
/// Rust ↔ UI bridge works end to end.
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

/// Builds and runs the Tauri application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![engine_status])
        .run(tauri::generate_context!())
        .expect("error while running Deadband");
}
