//! The canary PLC (feature program, item 3).
//!
//! A fake Modbus/TCP controller that nothing legitimate ever talks
//! to — it is not in the plant's real inventory, no HMI polls it, no
//! historian reads it. Any connection to it, any request at all, is
//! an intruder by definition: no baseline, no false positives, no
//! threshold to tune. The touch *is* the alert.
//!
//! ## The passive-only boundary, stated plainly
//!
//! The monitor itself is passive-only, forever — it reads copies of
//! traffic and never transmits. The canary is the deliberate,
//! opt-in exception, and it is a *decoy*, not the monitor: it is off
//! by default, the user starts it by hand, it answers only requests
//! addressed to itself, and it never talks to a real device. A
//! silent decoy teaches nothing — an attacker who connects and gets
//! nothing back leaves. So the canary answers, plausibly, with fake
//! process values — and records everything the visitor does. The
//! twin (feature program, last item) reuses this responder.
//!
//! ## How it runs
//!
//! [`CanaryServer::start`] binds a TCP listener (default port 502,
//! the real Modbus port) and spawns one thread per connection. Each
//! request is answered by the pure [`respond`] function and reported
//! to the caller through the `on_touch` callback as a
//! [`CanaryTouch`]; the shell turns touches into stored alert events
//! and device rows. Touches bypass `process_packet_full` on purpose:
//! canary traffic must never train the anomaly baseline — the
//! visitor is not normal, whatever they do.
//!
//! ## Ports
//!
//! Ports below 1024 need admin rights on macOS/Linux, so binding
//! 502 as a normal user fails with a plain-English error naming
//! that step; port 1502 is the no-sudo lab alternative. The server
//! binds `0.0.0.0` by default so anything on the network can reach
//! it — a decoy only on loopback catches nobody.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::model::{Event, EventKind};

/// The real Modbus/TCP port. Binding it needs admin rights — see
/// [`LAB_PORT`] for the no-sudo lab alternative.
pub const DEFAULT_PORT: u16 = 502;

/// The lab port: above 1024, so a normal user can bind it.
pub const LAB_PORT: u16 = 1502;

/// Default bind address: every interface, so anything on the network
/// can reach the decoy.
pub const DEFAULT_BIND: &str = "0.0.0.0";

/// A visitor doing something to the canary. `function == 0` is a
/// bare connection (connected, no Modbus request yet); anything else
/// is a Modbus request that got answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryTouch {
    /// Who touched it.
    pub src_ip: IpAddr,
    /// Their source port.
    pub src_port: u16,
    /// Modbus function code, or 0 for a bare connection.
    pub function: u8,
    /// Plain-English detail ("read holding registers, addr 0, 10 regs").
    pub detail: String,
    /// When it happened, Unix seconds.
    pub timestamp_s: i64,
}

/// What the canary listens on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryConfig {
    /// Bind address, e.g. "0.0.0.0".
    pub bind: String,
    /// TCP port, usually 502 (or 1502 without admin rights).
    pub port: u16,
}

impl Default for CanaryConfig {
    fn default() -> CanaryConfig {
        CanaryConfig { bind: DEFAULT_BIND.to_string(), port: DEFAULT_PORT }
    }
}

/// Plain-English name of a Modbus function code — the same names
/// the parser uses, so the log reads the same either way.
pub fn function_name(function: u8) -> &'static str {
    match function {
        1 => "read coils",
        2 => "read discrete inputs",
        3 => "read holding registers",
        4 => "read input registers",
        5 => "write single coil",
        6 => "write single register",
        15 => "write multiple coils",
        16 => "write multiple registers",
        _ => "modbus function",
    }
}

/// A decoded Modbus request: enough to answer it and to describe
/// the touch in plain English.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedRequest {
    function: u8,
    address: u16,
    quantity: u16,
    value: u16,
}

/// Decodes one framed Modbus/TCP request (MBAP header + PDU).
/// Returns `None` for framing-level problems (bad protocol id, a
/// length field smaller than unit + function) — the caller closes
/// the connection instead of answering garbage.
fn parse_request(frame: &[u8]) -> Option<ParsedRequest> {
    if frame.len() < 8 {
        return None;
    }
    let protocol = u16::from_be_bytes([frame[2], frame[3]]);
    if protocol != 0 {
        return None;
    }
    let length = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    if length < 2 || frame.len() < 6 + length {
        return None;
    }
    let function = frame[7];
    let data = &frame[8..6 + length];
    let address = data.first().copied().map(|b| u16::from_be_bytes([b, data.get(1).copied().unwrap_or(0)])).unwrap_or(0);
    let quantity = if data.len() >= 4 {
        u16::from_be_bytes([data[2], data[3]])
    } else if data.len() >= 2 {
        u16::from_be_bytes([data[0], data[1]])
    } else {
        0
    };
    let value = quantity;
    Some(ParsedRequest { function, address, quantity, value })
}

/// Plain-English detail for a touch, from the decoded request.
fn touch_detail(req: &ParsedRequest) -> String {
    let name = function_name(req.function);
    match req.function {
        1 | 2 | 3 | 4 => format!("{name}, addr {}, {} values", req.address, req.quantity),
        5 | 6 => format!("{name}, addr {} = {}", req.address, req.value),
        15 | 16 => format!("{name}, addr {}, {} values", req.address, req.quantity),
        _ => format!("{name} (function {})", req.function),
    }
}

/// Builds the MBAP header for a response: same transaction id and
/// unit id as the request, protocol 0, length = unit + function +
/// data.
fn mbap_response(frame: &[u8], pdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + pdu.len());
    out.extend_from_slice(&frame[0..2]); // transaction id
    out.extend_from_slice(&[0, 0]); // protocol id
    let length = (1 + pdu.len()) as u16;
    out.extend_from_slice(&length.to_be_bytes());
    out.push(frame[6]); // unit id
    out.extend_from_slice(pdu);
    out
}

/// A Modbus exception response: function | 0x80, exception code.
fn exception_response(frame: &[u8], code: u8) -> Vec<u8> {
    mbap_response(frame, &[frame[7] | 0x80, code])
}

/// Answers one framed Modbus/TCP request with plausible fake data.
/// Pure function — no sockets, no threads — so the responder is
/// testable without a network. Returns `None` when the frame is not
/// answerable (framing-level garbage); the caller closes the
/// connection.
///
/// Fake values are deterministic per address with a slow drift from
/// `now_s`, so a visitor who reads twice sees a living process, not
/// a frozen one.
pub fn respond(frame: &[u8], now_s: i64) -> Option<Vec<u8>> {
    let req = parse_request(frame)?;
    let function = req.function;
    match function {
        1 | 2 => {
            // Read coils / discrete inputs: 1..=2000 bits.
            if req.quantity == 0 || req.quantity > 2000 {
                return Some(exception_response(frame, 0x03));
            }
            let byte_count = (req.quantity as usize + 7) / 8;
            let mut pdu = vec![function, byte_count as u8];
            for i in 0..byte_count {
                let mut byte = 0u8;
                for bit in 0..8 {
                    let idx = (i * 8 + bit) as u16;
                    if idx < req.quantity && (req.address + idx) % 5 == 0 {
                        byte |= 1 << bit;
                    }
                }
                pdu.push(byte);
            }
            Some(mbap_response(frame, &pdu))
        }
        3 | 4 => {
            // Read registers: 1..=125 registers, two bytes each.
            if req.quantity == 0 || req.quantity > 125 {
                return Some(exception_response(frame, 0x03));
            }
            let mut pdu = vec![function, (req.quantity * 2) as u8];
            let drift = ((now_s / 10) % 40) as u16;
            for i in 0..req.quantity {
                let value = 1000u16
                    .wrapping_add(req.address.wrapping_mul(13))
                    .wrapping_add(i.wrapping_mul(7))
                    .wrapping_add(drift);
                pdu.extend_from_slice(&value.to_be_bytes());
            }
            Some(mbap_response(frame, &pdu))
        }
        5 | 6 => {
            // Write single coil / register: echo the request PDU.
            if frame.len() < 12 {
                return Some(exception_response(frame, 0x03));
            }
            Some(mbap_response(frame, &frame[7..12]))
        }
        15 | 16 => {
            // Write multiple: echo function, address, quantity.
            if frame.len() < 12 {
                return Some(exception_response(frame, 0x03));
            }
            Some(mbap_response(frame, &frame[7..12]))
        }
        _ => Some(exception_response(frame, 0x01)),
    }
}

/// The stored alert event for a touch: kind `AlertRaised`, the
/// visitor as source, the canary as destination. The touch *is* the
/// alert — no rule or threshold sits between the visitor and the
/// log.
pub fn touch_event(touch: &CanaryTouch, canary_ip: IpAddr) -> Event {
    let summary = if touch.function == 0 {
        format!(
            "Canary PLC touched — {} connected (no Modbus request yet). Nothing legitimate talks to the canary: this is an intruder.",
            touch.src_ip
        )
    } else {
        format!(
            "Canary PLC touched — {} {} ({}). Nothing legitimate talks to the canary: this is an intruder.",
            touch.src_ip,
            function_name(touch.function),
            touch.detail
        )
    };
    let mut event = Event::new(touch.timestamp_s, EventKind::AlertRaised, summary);
    event.src_ip = Some(touch.src_ip);
    event.dst_ip = Some(canary_ip);
    event
}

fn now_s() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A running canary: the listener thread plus its stop flag.
/// Dropping it does not stop it — call [`CanaryServer::stop`].
pub struct CanaryServer {
    stop: Arc<AtomicBool>,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    addr: SocketAddr,
}

impl std::fmt::Debug for CanaryServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanaryServer").field("addr", &self.addr).finish()
    }
}

impl CanaryServer {
    /// Binds and starts the canary. `on_touch` is called from the
    /// connection threads (potentially several at once) for every
    /// connection and every request. Errors are plain English: a
    /// permission refusal names the admin step, an occupied port
    /// names the port.
    pub fn start(
        config: &CanaryConfig,
        on_touch: impl Fn(CanaryTouch) + Send + Sync + 'static,
    ) -> Result<CanaryServer, String> {
        let listener = TcpListener::bind((config.bind.as_str(), config.port)).map_err(|e| {
            use std::io::ErrorKind::*;
            match e.kind() {
                PermissionDenied => format!(
                    "Could not listen on port {} — ports below 1024 need admin rights. Run with sudo for a lab test, or use port {} instead.",
                    config.port, LAB_PORT
                ),
                AddrInUse => format!(
                    "Port {} is already in use — something else is listening there. Pick another port, or stop the other service.",
                    config.port
                ),
                _ => format!("Could not listen on {}:{} — {e}", config.bind, config.port),
            }
        })?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("Could not read the canary's address — {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("Could not set up the canary listener — {e}"))?;
        let on_touch = Arc::new(on_touch);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            serve(listener, on_touch, stop_flag);
        });
        Ok(CanaryServer {
            stop,
            handle: Mutex::new(Some(handle)),
            addr,
        })
    }

    /// The address the canary is actually listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops the canary: the accept loop exits within ~20 ms; open
    /// connections are left to their read timeout (a few seconds)
    /// and then close on their own.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut handle) = self.handle.lock() {
            if let Some(handle) = handle.take() {
                let _ = handle.join();
            }
        }
    }
}

/// The accept loop: non-blocking accepts so the stop flag is
/// checked regularly; each connection gets its own handler thread.
fn serve(listener: TcpListener, on_touch: Arc<dyn Fn(CanaryTouch) + Send + Sync>, stop: Arc<AtomicBool>) {
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                let on_touch = Arc::clone(&on_touch);
                std::thread::spawn(move || {
                    handle_connection(stream, peer, on_touch);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => {
                // The listener is gone (or broken) — nothing more
                // to accept. The server is done.
                break;
            }
        }
    }
}

/// One visitor: report the connection, then read Modbus frames,
/// answer each, and report each request. Frames can arrive split
/// across TCP segments or several at once, so bytes accumulate in a
/// buffer and are consumed per the MBAP length field. A connection
/// that sends nothing for 5 s, or sends garbage, is closed.
fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    on_touch: Arc<dyn Fn(CanaryTouch) + Send + Sync>,
) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let _ = stream.set_nodelay(true);
    on_touch(CanaryTouch {
        src_ip: peer.ip(),
        src_port: peer.port(),
        function: 0,
        detail: "connected".to_string(),
        timestamp_s: now_s(),
    });
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break, // peer closed
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break, // timeout or read error: close
        }
        loop {
            if buf.len() < 8 {
                break;
            }
            let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
            if length < 2 || length > 4096 {
                return; // garbage framing: close
            }
            let total = 6 + length;
            if buf.len() < total {
                break; // wait for the rest of the frame
            }
            let frame: Vec<u8> = buf.drain(..total).collect();
            let req = match parse_request(&frame) {
                Some(req) => req,
                None => return, // unanswerable: close
            };
            let detail = touch_detail(&req);
            let function = req.function;
            match respond(&frame, now_s()) {
                Some(response) => {
                    if stream.write_all(&response).is_err() {
                        return;
                    }
                }
                None => return,
            }
            on_touch(CanaryTouch {
                src_ip: peer.ip(),
                src_port: peer.port(),
                function,
                detail,
                timestamp_s: now_s(),
            });
        }
        if buf.len() > 65536 {
            return; // never a full frame: close
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    fn fc3_frame(tx: u16, address: u16, quantity: u16) -> Vec<u8> {
        let mut f = vec![];
        f.extend_from_slice(&tx.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&6u16.to_be_bytes());
        f.push(1); // unit id
        f.push(3); // read holding registers
        f.extend_from_slice(&address.to_be_bytes());
        f.extend_from_slice(&quantity.to_be_bytes());
        f
    }

    #[test]
    fn fc3_read_answers_with_fake_registers() {
        let frame = fc3_frame(0x1234, 0, 2);
        let resp = respond(&frame, 1_700_000_000).expect("a read is answerable");
        assert_eq!(&resp[0..2], &[0x12, 0x34], "transaction id echoed");
        assert_eq!(&resp[2..4], &[0, 0], "protocol id is 0");
        assert_eq!(resp[6], 1, "unit id echoed");
        assert_eq!(resp[7], 3, "function echoed");
        assert_eq!(resp[8], 4, "two registers = four data bytes");
        // Values are deterministic per address + slow drift.
        let v0 = u16::from_be_bytes([resp[9], resp[10]]);
        let v1 = u16::from_be_bytes([resp[11], resp[12]]);
        assert_eq!(v1 - v0, 7, "registers step by 7");
        let again = respond(&frame, 1_700_000_000).unwrap();
        assert_eq!(resp, again, "same second, same answer");
        let later = respond(&frame, 1_700_000_030).unwrap();
        assert_ne!(resp, later, "values drift slowly over time");
    }

    #[test]
    fn fc6_write_is_echoed() {
        let mut frame = fc3_frame(7, 200, 999);
        frame[7] = 6; // write single register
        let resp = respond(&frame, 1_700_000_000).expect("a write is answerable");
        assert_eq!(resp[7], 6);
        assert_eq!(&resp[8..12], &[0, 200, 3, 231], "address + value echoed");
    }

    #[test]
    fn fc1_read_answers_coils() {
        let mut frame = fc3_frame(9, 0, 10);
        frame[7] = 1; // read coils
        let resp = respond(&frame, 1_700_000_000).expect("a coil read is answerable");
        assert_eq!(resp[7], 1);
        assert_eq!(resp[8], 2, "ten coils = two bytes");
    }

    #[test]
    fn unknown_function_gets_an_exception() {
        let mut frame = fc3_frame(3, 0, 1);
        frame[7] = 17;
        let resp = respond(&frame, 1_700_000_000).expect("unknown functions get an exception");
        assert_eq!(resp[7], 17 | 0x80);
        assert_eq!(resp[8], 0x01, "illegal function");
    }

    #[test]
    fn malformed_frames_are_not_answered() {
        assert!(respond(&[], 0).is_none(), "empty");
        assert!(respond(&[0, 1, 0, 0], 0).is_none(), "short header");
        let mut bad_proto = fc3_frame(1, 0, 1);
        bad_proto[2] = 0;
        bad_proto[3] = 1; // protocol id 1, not Modbus/TCP
        assert!(respond(&bad_proto, 0).is_none(), "bad protocol id");
    }

    #[test]
    fn touch_event_names_the_visitor_and_the_request() {
        let touch = CanaryTouch {
            src_ip: "192.168.1.50".parse().unwrap(),
            src_port: 52341,
            function: 3,
            detail: "read holding registers, addr 0, 10 values".to_string(),
            timestamp_s: 1_700_000_000,
        };
        let event = touch_event(&touch, "192.168.1.20".parse().unwrap());
        assert!(matches!(event.kind, EventKind::AlertRaised));
        assert_eq!(event.src_ip.unwrap().to_string(), "192.168.1.50");
        assert_eq!(event.dst_ip.unwrap().to_string(), "192.168.1.20");
        assert!(event.summary.contains("192.168.1.50"), "names the visitor");
        assert!(event.summary.contains("read holding registers"), "names the request");
        assert!(event.summary.contains("Canary PLC"), "names the canary");
    }

    #[test]
    fn server_answers_a_real_connection_and_reports_touches() {
        let seen: Arc<Mutex<Vec<CanaryTouch>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = Arc::clone(&seen);
        let server = CanaryServer::start(
            &CanaryConfig { bind: "127.0.0.1".to_string(), port: 0 },
            move |touch| {
                seen_clone.lock().unwrap().push(touch);
            },
        )
        .expect("ephemeral port binds");
        let port = server.addr().port();
        assert_ne!(port, 0, "the OS assigned a port");

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        stream.write_all(&fc3_frame(0x42, 0, 2)).unwrap();
        let mut resp = [0u8; 64];
        let n = stream.read(&mut resp).expect("reads a response");
        assert!(n >= 13, "a full MBAP response came back, got {n} bytes");
        assert_eq!(&resp[0..2], &[0, 0x42], "transaction id echoed over the wire");
        assert_eq!(resp[7], 3);
        drop(stream);
        std::thread::sleep(std::time::Duration::from_millis(200));
        server.stop();

        let touches = seen.lock().unwrap();
        assert!(touches.iter().any(|t| t.function == 0), "the connection itself was reported");
        let req = touches.iter().find(|t| t.function == 3).expect("the read was reported");
        assert_eq!(req.src_ip.to_string(), "127.0.0.1");
        assert!(req.detail.contains("read holding registers"), "detail names the request");
        // Stopped: nothing listens any more.
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "stop closes the listener");
    }

    #[test]
    fn occupied_port_fails_in_plain_english() {
        let held = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        let err = CanaryServer::start(
            &CanaryConfig { bind: "127.0.0.1".to_string(), port },
            |_| {},
        )
        .unwrap_err();
        assert!(err.contains("already in use"), "names the problem: {err}");
        assert!(err.contains(&port.to_string()), "names the port");
    }
}
