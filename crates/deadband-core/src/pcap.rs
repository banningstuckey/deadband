//! PCAP files: the classic libpcap capture format that Wireshark and
//! tcpdump write. Phase 3 teaches Deadband to eat recordings — the
//! same packets a sensor would have seen live, replayed through the
//! identical pipeline.
//!
//! Format notes (from the libpcap spec): a 24-byte global header
//! (magic, version, snap length, link type), then per-packet records
//! of a 16-byte header (timestamp seconds + fraction, captured length,
//! original length) followed by the frame bytes. The magic number's
//! byte order reveals both the file's endianness and whether the
//! fraction is microseconds or nanoseconds; all four combinations
//! occur in the wild and all four are handled.
//!
//! Paranoid, like the packet parser: every length is checked against
//! what actually remains in the buffer, absurd record sizes are
//! rejected, and nothing in here can panic on a hostile file.

use crate::source::{Packet, TrafficSource};
use std::fmt;

/// Why a capture file could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapError {
    /// Fewer bytes than even the global header needs.
    TooShort,
    /// First four bytes are not any known pcap magic.
    BadMagic,
    /// The capture's link type is not Ethernet (Deadband v1 speaks
    /// Ethernet captures; Wireshark's default on real interfaces).
    UnsupportedLinkType(u32),
    /// A record header claims more data than the file holds
    /// (truncated download, or a capture cut mid-write).
    TruncatedRecord,
    /// A record claims an implausible frame size.
    RecordTooLarge(u32),
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::TooShort => write!(f, "file is too short to be a pcap capture"),
            PcapError::BadMagic => write!(f, "not a pcap file (bad magic number)"),
            PcapError::UnsupportedLinkType(kind) => {
                write!(f, "unsupported link type {kind} (only Ethernet captures for now)")
            }
            PcapError::TruncatedRecord => write!(f, "capture ends mid-packet (truncated file)"),
            PcapError::RecordTooLarge(size) => write!(f, "implausible packet size in capture: {size} bytes"),
        }
    }
}

impl std::error::Error for PcapError {}

/// LINKTYPE_ETHERNET.
const LINKTYPE_ETHERNET: u32 = 1;
/// No real Ethernet frame is anywhere near this; a record claiming
/// more is corrupt, not jumbo.
const MAX_FRAME_BYTES: u32 = 1 << 20;

/// How the file's multi-byte fields are laid out, decoded from magic.
#[derive(Clone, Copy)]
struct Layout {
    little_endian: bool,
    nanoseconds: bool,
}

impl Layout {
    fn u32(&self, bytes: &[u8]) -> u32 {
        let raw = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if self.little_endian {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        }
    }
}

fn layout_of(magic: &[u8]) -> Option<Layout> {
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => Some(Layout { little_endian: true, nanoseconds: false }),
        [0xa1, 0xb2, 0xc3, 0xd4] => Some(Layout { little_endian: false, nanoseconds: false }),
        [0x4d, 0x3c, 0xb2, 0xa1] => Some(Layout { little_endian: true, nanoseconds: true }),
        [0xa1, 0xb2, 0x3c, 0x4d] => Some(Layout { little_endian: false, nanoseconds: true }),
        _ => None,
    }
}

/// Reads a whole pcap file (already in memory) into packets, keeping
/// the capture's own timestamps.
pub fn read_pcap(bytes: &[u8]) -> Result<Vec<Packet>, PcapError> {
    if bytes.len() < 24 {
        return Err(PcapError::TooShort);
    }
    let layout = layout_of(&bytes[0..4]).ok_or(PcapError::BadMagic)?;
    let link_type = layout.u32(&bytes[20..24]);
    if link_type != LINKTYPE_ETHERNET {
        return Err(PcapError::UnsupportedLinkType(link_type));
    }
    let mut packets = Vec::new();
    let mut offset = 24usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            return Err(PcapError::TruncatedRecord);
        }
        let record = &bytes[offset..offset + 16];
        let ts_sec = layout.u32(&record[0..4]) as i64;
        let ts_frac = layout.u32(&record[4..8]) as i64;
        let incl_len = layout.u32(&record[8..12]);
        if incl_len > MAX_FRAME_BYTES {
            return Err(PcapError::RecordTooLarge(incl_len));
        }
        let incl_len = incl_len as usize;
        let data_start = offset + 16;
        if bytes.len() - data_start < incl_len {
            return Err(PcapError::TruncatedRecord);
        }
        let frac_ms = if layout.nanoseconds { ts_frac / 1_000_000 } else { ts_frac / 1_000 };
        packets.push(Packet {
            timestamp_ms: ts_sec * 1000 + frac_ms,
            data: bytes[data_start..data_start + incl_len].to_vec(),
        });
        offset = data_start + incl_len;
    }
    Ok(packets)
}

/// Writes packets as a pcap file (little-endian, microsecond
/// timestamps) — how Deadband exports captures of its own, and how
/// the bundled sample capture is produced in tests.
pub fn write_pcap(packets: &[Packet]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // LE micro magic
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
    for packet in packets {
        let ts_sec = (packet.timestamp_ms / 1000) as u32;
        let ts_usec = ((packet.timestamp_ms % 1000) * 1000) as u32;
        out.extend_from_slice(&ts_sec.to_le_bytes());
        out.extend_from_slice(&ts_usec.to_le_bytes());
        out.extend_from_slice(&(packet.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(packet.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&packet.data);
    }
    out
}

/// A capture replayed as a traffic source: finite, in file order,
/// timestamps preserved. The caller paces playback.
pub struct PcapSource {
    label: String,
    packets: std::vec::IntoIter<Packet>,
}

impl PcapSource {
    pub fn new(label: impl Into<String>, packets: Vec<Packet>) -> PcapSource {
        PcapSource { label: label.into(), packets: packets.into_iter() }
    }
}

impl TrafficSource for PcapSource {
    fn name(&self) -> &str {
        &self.label
    }

    fn next_packet(&mut self) -> Option<Packet> {
        self.packets.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::Plant;

    fn some_packets() -> Vec<Packet> {
        let mut plant = Plant::new();
        (0..30).map(|_| plant.next_packet(1_700_000_000_000)).collect()
    }

    #[test]
    fn write_then_read_round_trips() {
        let packets = some_packets();
        let bytes = write_pcap(&packets);
        let back = read_pcap(&bytes).expect("our own pcap must read");
        assert_eq!(back.len(), packets.len());
        for (a, b) in packets.iter().zip(back.iter()) {
            assert_eq!(a.data, b.data);
            // pcap stores whole milliseconds here exactly.
            assert_eq!(a.timestamp_ms, b.timestamp_ms);
        }
    }

    #[test]
    fn nanosecond_big_endian_header_parses() {
        // Hand-build a BE/nano file with one 4-byte "frame".
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xa1, 0xb2, 0x3c, 0x4d]);
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&0i32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&65535u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&10u32.to_be_bytes()); // ts sec
        bytes.extend_from_slice(&500_000_000u32.to_be_bytes()); // ts nano = 500 ms
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.extend_from_slice(&4u32.to_be_bytes());
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        let packets = read_pcap(&bytes).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].timestamp_ms, 10_500);
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        assert_eq!(read_pcap(&[0u8; 10]), Err(PcapError::TooShort));
        let mut junk = vec![0u8; 24];
        junk[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(read_pcap(&junk), Err(PcapError::BadMagic));
        let mut bytes = write_pcap(&some_packets());
        bytes.truncate(bytes.len() - 3);
        assert_eq!(read_pcap(&bytes), Err(PcapError::TruncatedRecord));
    }

    #[test]
    fn rejects_non_ethernet_link_type() {
        let mut bytes = write_pcap(&some_packets());
        bytes[20..24].copy_from_slice(&113u32.to_le_bytes()); // LINKTYPE_LINUX_SLL
        assert_eq!(read_pcap(&bytes), Err(PcapError::UnsupportedLinkType(113)));
    }

    #[test]
    fn pcap_source_drains_in_order_then_ends() {
        let packets = some_packets();
        let total = packets.len();
        let mut source = PcapSource::new("test-capture", packets);
        assert_eq!(source.name(), "test-capture");
        let mut seen = 0;
        while source.next_packet().is_some() {
            seen += 1;
        }
        assert_eq!(seen, total);
        assert!(source.next_packet().is_none());
    }
}
