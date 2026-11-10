//! The bundled sample capture: ~75 seconds of a *foreign* plant's
//! traffic, generated deterministically from the simulated plant but
//! re-addressed onto a different subnet (192.168.50.0/24) and salted
//! with one device the plant roster knows nothing about.
//!
//! Why it exists: Phase 3's discovery demo must work out of the box,
//! with no downloads and no licensing questions. Deadband has never
//! been told these devices exist and registers nothing in advance —
//! replaying this capture, the inventory, map, and conduits must all
//! be *discovered from the wire*, exactly as with a real capture.
//!
//! The salt: at 192.168.50.77 there is a "field laptop" that polls
//! Line 1 every ~11 seconds and, once, at t≈52s, writes a setpoint of
//! 999 to it. An unknown device writing to a PLC is precisely the
//! pattern Phase 4's rules will exist to catch; here it is just
//! quietly visible in the log for anyone who looks.

use crate::sim::{
    build_modbus_read, build_modbus_read_response, build_modbus_write_single, build_tcp_frame,
    Plant,
};
use crate::source::Packet;

/// The mystery device in the sample capture.
pub const LAPTOP_IP: [u8; 4] = [192, 168, 50, 77];
const LAPTOP_MAC: &str = "02:db:00:00:32:4d";
const LAPTOP_PORT: u16 = 40077;

/// (old ip, new ip, new mac) for each roster device, plant → sample.
const ADDRESS_MAP: [([u8; 4], [u8; 4], &str); 5] = [
    ([10, 0, 4, 10], [192, 168, 50, 10], "02:db:00:00:32:0a"), // office PC
    ([10, 0, 3, 20], [192, 168, 50, 20], "02:db:00:00:32:14"), // historian
    ([10, 0, 2, 10], [192, 168, 50, 30], "02:db:00:00:32:1e"), // HMI
    ([10, 0, 1, 11], [192, 168, 50, 41], "02:db:00:00:32:29"), // Line 1 PLC
    ([10, 0, 1, 12], [192, 168, 50, 42], "02:db:00:00:32:2a"), // Line 2 PLC
];

const PLC1_NEW: [u8; 4] = [192, 168, 50, 41];
const PLC1_NEW_MAC: &str = "02:db:00:00:32:29";

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn lookup(ip: [u8; 4]) -> Option<([u8; 4], &'static str)> {
    ADDRESS_MAP.iter().find(|(old, _, _)| *old == ip).map(|(_, new, mac)| (*new, *mac))
}

fn parse_mac(mac: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (i, part) in mac.split(':').enumerate().take(6) {
        out[i] = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    out
}

/// Re-addresses one plant frame onto the sample subnet, fixing the
/// Ethernet addresses and both checksums the move invalidates.
fn rewrite_frame(frame: &[u8]) -> Vec<u8> {
    let mut out = frame.to_vec();
    if out.len() < 54 {
        return out;
    }
    let src_ip: [u8; 4] = out[26..30].try_into().unwrap();
    let dst_ip: [u8; 4] = out[30..34].try_into().unwrap();
    if let Some((new_src, new_src_mac)) = lookup(src_ip) {
        out[26..30].copy_from_slice(&new_src);
        out[6..12].copy_from_slice(&parse_mac(new_src_mac));
    }
    if let Some((new_dst, new_dst_mac)) = lookup(dst_ip) {
        out[30..34].copy_from_slice(&new_dst);
        out[0..6].copy_from_slice(&parse_mac(new_dst_mac));
    }
    // IPv4 header checksum.
    out[24..26].copy_from_slice(&[0, 0]);
    let ip_sum = checksum(&out[14..34]);
    out[24..26].copy_from_slice(&ip_sum.to_be_bytes());
    // TCP checksum (pseudo-header + segment).
    let ip_total = u16::from_be_bytes([out[16], out[17]]) as usize;
    let tcp_len = ip_total.saturating_sub(20);
    out[50..52].copy_from_slice(&[0, 0]);
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&out[26..30]);
    pseudo.extend_from_slice(&out[30..34]);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&out[34..34 + tcp_len]);
    let tcp_sum = checksum(&pseudo);
    out[50..52].copy_from_slice(&tcp_sum.to_be_bytes());
    out
}

fn modbus_adu(transaction: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut adu = Vec::with_capacity(7 + pdu.len());
    adu.extend_from_slice(&transaction.to_be_bytes());
    adu.extend_from_slice(&0u16.to_be_bytes());
    adu.extend_from_slice(&((pdu.len() + 1) as u16).to_be_bytes());
    adu.push(unit);
    adu.extend_from_slice(pdu);
    adu
}

/// The laptop's traffic: periodic reads of Line 1, then one write.
fn laptop_packets() -> Vec<Packet> {
    let mut packets = Vec::new();
    let values: [u16; 8] = [101, 202, 303, 404, 505, 606, 707, 808];
    for (i, at_ms) in [8_000i64, 19_000, 30_000, 41_000].iter().enumerate() {
        let seq = 5000 + (i as u32) * 2;
        packets.push(Packet {
            timestamp_ms: *at_ms,
            data: build_modbus_read(
                LAPTOP_MAC, PLC1_NEW_MAC, LAPTOP_IP, PLC1_NEW, LAPTOP_PORT, 1, 3, 0, 8, seq,
            ),
        });
        packets.push(Packet {
            timestamp_ms: at_ms + 12,
            data: build_modbus_read_response(
                PLC1_NEW_MAC, LAPTOP_MAC, PLC1_NEW, LAPTOP_IP, LAPTOP_PORT, 1, 3, &values, seq + 1,
            ),
        });
    }
    // The write: function 6, register 200, value 999 — far outside the
    // HMI's usual 380–460 band.
    packets.push(Packet {
        timestamp_ms: 52_000,
        data: build_modbus_write_single(
            LAPTOP_MAC, PLC1_NEW_MAC, LAPTOP_IP, PLC1_NEW, LAPTOP_PORT, 1, 200, 999, 5100,
        ),
    });
    let mut pdu = vec![6u8];
    pdu.extend_from_slice(&200u16.to_be_bytes());
    pdu.extend_from_slice(&999u16.to_be_bytes());
    let adu = modbus_adu(5101, 1, &pdu);
    packets.push(Packet {
        timestamp_ms: 52_012,
        data: build_tcp_frame(
            PLC1_NEW_MAC, LAPTOP_MAC, PLC1_NEW, LAPTOP_IP, 502, LAPTOP_PORT, &adu, 5101,
        ),
    });
    packets
}

/// The full sample capture, packets in timestamp order, timestamps
/// relative to the capture start (the shell rebases them to "now"
/// when replaying, so the log reads as live).
pub fn sample_packets() -> Vec<Packet> {
    let mut plant = Plant::new();
    let mut packets = Vec::new();
    loop {
        let packet = plant.next_packet(0);
        if packet.timestamp_ms > 75_000 {
            break;
        }
        packets.push(Packet { timestamp_ms: packet.timestamp_ms, data: rewrite_frame(&packet.data) });
    }
    packets.extend(laptop_packets());
    packets.sort_by_key(|p| p.timestamp_ms);
    packets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine;
    use crate::model::EventKind;
    use crate::store::Store;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn sample_is_deterministic_and_mostly_foreign() {
        let a = sample_packets();
        let b = sample_packets();
        assert_eq!(a, b);
        assert!(a.len() > 200, "75 s of plant traffic, got {}", a.len());
        // Every plant frame was re-addressed off the 10.0.x.x lab net.
        let parsed = crate::parse::parse_packet(&a[0]).unwrap();
        assert_eq!(parsed.src_ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 30))));
    }

    #[test]
    fn replaying_the_sample_discovers_six_unknown_devices() {
        let store = Store::open_in_memory().unwrap();
        let mut laptop_writes = 0;
        for packet in sample_packets() {
            for event in engine::process_packet(&store, &packet) {
                if let EventKind::ModbusCommand { is_write: true, .. } = event.kind {
                    if event.src_ip == Some(IpAddr::V4(Ipv4Addr::from(LAPTOP_IP))) {
                        laptop_writes += 1;
                    }
                }
            }
        }
        let devices = store.list_devices().unwrap();
        assert_eq!(devices.len(), 6, "5 re-addressed plant devices + the laptop");
        assert!(
            devices.iter().all(|d| d.level.is_none()),
            "nothing was registered in advance: every device is unplaced"
        );
        assert_eq!(laptop_writes, 1, "the laptop's one quiet write is in the log");
    }
}
