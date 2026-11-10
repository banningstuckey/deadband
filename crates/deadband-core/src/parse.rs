//! Packet parsing: raw bytes in, structured facts out.
//!
//! Phase 1 implements the decode chain the pipeline needs:
//! Ethernet II → IPv4 → TCP/UDP → Modbus/TCP (port 502). Anything else
//! is classified as plain TCP/UDP or rejected with a typed error.
//! Phase 3 hardens the same code against real-world captures.
//!
//! Parsing is a pure function of the packet bytes. It performs no I/O
//! and — per the project's safety rules — never crafts response packets.
//! Real plant traffic is untrusted input: every length field is treated
//! as a lie until checked, and no input may cause a panic.

use crate::model::Protocol;
use crate::source::Packet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// The standard Modbus/TCP port.
pub const MODBUS_PORT: u16 = 502;

/// The Modbus facts lifted out of a Modbus/TCP packet — the fields
/// detection actually reasons about. (Full register values are process
/// data; a security monitor mostly needs *who commanded what, how*.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModbusInfo {
    /// Modbus unit/slave id the command addresses.
    pub unit_id: u8,
    /// Function code (1–4 reads, 5/6/15/16 writes, …). For exception
    /// responses the high bit is stripped, so this is the code of the
    /// request that failed.
    pub function_code: u8,
    /// True when the function code changes state on the target
    /// (write coil/register, etc.) — writes from unexpected sources are
    /// among the highest-signal events in OT monitoring.
    pub is_write: bool,
    /// True for responses travelling server → client; exception
    /// responses (the request was refused/failed) also set
    /// `is_exception`.
    pub is_response: bool,
    /// True when the server answered with a Modbus exception.
    pub is_exception: bool,
    /// Start address for read/write requests (register/coil number).
    pub address: Option<u16>,
    /// Quantity for read requests and multi-writes.
    pub quantity: Option<u16>,
    /// Value for single writes (function codes 5 and 6).
    pub value: Option<u16>,
}

impl ModbusInfo {
    /// Plain-English name of the function code, as operators and
    /// textbooks call it.
    pub fn function_name(&self) -> &'static str {
        match self.function_code {
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
}

/// Function codes that change state on the target device.
pub fn is_write_function(function_code: u8) -> bool {
    matches!(function_code, 5 | 6 | 15 | 16)
}

/// A packet after parsing: the conversation it belongs to and, for
/// Modbus/TCP, the decoded command summary.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedPacket {
    /// Capture time, Unix milliseconds (carried from the raw packet).
    pub timestamp_ms: i64,
    /// Source IP, when an IP header was present.
    pub src_ip: Option<IpAddr>,
    /// Destination IP, when an IP header was present.
    pub dst_ip: Option<IpAddr>,
    /// Source port, for TCP/UDP.
    pub src_port: Option<u16>,
    /// Destination port, for TCP/UDP.
    pub dst_port: Option<u16>,
    /// Best protocol identification.
    pub protocol: Protocol,
    /// Decoded Modbus facts; `Some` only for Modbus/TCP packets.
    pub modbus: Option<ModbusInfo>,
    /// Total frame length in bytes.
    pub length: usize,
}

/// Why a packet could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Zero-length input — nothing to parse.
    Empty,
    /// Truncated or malformed at a named layer ("ethernet", "ipv4", …).
    Malformed(&'static str),
    /// Well-formed, but a protocol Deadband does not decode.
    Unsupported(&'static str),
    /// The decoder for this protocol lands in a later phase.
    NotImplemented(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty packet"),
            ParseError::Malformed(layer) => write!(f, "malformed {layer} header"),
            ParseError::Unsupported(proto) => write!(f, "unsupported protocol: {proto}"),
            ParseError::NotImplemented(what) => write!(f, "not implemented yet: {what}"),
        }
    }
}

impl std::error::Error for ParseError {}

fn u16be(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// Parses one raw packet (an Ethernet II frame, as every Deadband
/// source supplies) into a [`ParsedPacket`].
pub fn parse_packet(packet: &Packet) -> Result<ParsedPacket, ParseError> {
    let data = &packet.data;
    if data.is_empty() {
        return Err(ParseError::Empty);
    }
    // Ethernet II: 6 dst MAC + 6 src MAC + 2 EtherType.
    if data.len() < 14 {
        return Err(ParseError::Malformed("ethernet"));
    }
    let ethertype = u16be(data, 12);
    let payload = &data[14..];
    match ethertype {
        0x0800 => parse_ipv4(packet.timestamp_ms, payload, data.len()),
        0x86DD => Err(ParseError::Unsupported("ipv6")),
        _ => Err(ParseError::Unsupported("non-ip ethertype")),
    }
}

fn parse_ipv4(timestamp_ms: i64, ip: &[u8], frame_len: usize) -> Result<ParsedPacket, ParseError> {
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return Err(ParseError::Malformed("ipv4"));
    }
    let header_len = ((ip[0] & 0x0F) as usize) * 4;
    if header_len < 20 || ip.len() < header_len {
        return Err(ParseError::Malformed("ipv4"));
    }
    let total_len = u16be(ip, 2) as usize;
    if total_len < header_len || total_len > ip.len() {
        return Err(ParseError::Malformed("ipv4"));
    }
    let src_ip = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    let body = &ip[header_len..total_len];
    let mut parsed = ParsedPacket {
        timestamp_ms,
        src_ip: Some(src_ip),
        dst_ip: Some(dst_ip),
        src_port: None,
        dst_port: None,
        protocol: Protocol::Unknown,
        modbus: None,
        length: frame_len,
    };
    match ip[9] {
        6 => parse_tcp(&mut parsed, body)?,
        17 => parse_udp(&mut parsed, body)?,
        _ => return Err(ParseError::Unsupported("non-tcp/udp ip protocol")),
    }
    Ok(parsed)
}

fn parse_tcp(parsed: &mut ParsedPacket, tcp: &[u8]) -> Result<(), ParseError> {
    if tcp.len() < 20 {
        return Err(ParseError::Malformed("tcp"));
    }
    let header_len = ((tcp[12] >> 4) as usize) * 4;
    if header_len < 20 || tcp.len() < header_len {
        return Err(ParseError::Malformed("tcp"));
    }
    parsed.src_port = Some(u16be(tcp, 0));
    parsed.dst_port = Some(u16be(tcp, 2));
    parsed.protocol = Protocol::Tcp;
    let payload = &tcp[header_len..];
    if let Some(modbus) = parse_modbus(parsed.src_port, parsed.dst_port, payload) {
        parsed.protocol = Protocol::ModbusTcp;
        parsed.modbus = Some(modbus);
    }
    Ok(())
}

fn parse_udp(parsed: &mut ParsedPacket, udp: &[u8]) -> Result<(), ParseError> {
    if udp.len() < 8 {
        return Err(ParseError::Malformed("udp"));
    }
    parsed.src_port = Some(u16be(udp, 0));
    parsed.dst_port = Some(u16be(udp, 2));
    parsed.protocol = Protocol::Udp;
    Ok(())
}

/// Decodes a Modbus/TCP application data unit, if the payload is one.
/// Returns `None` for payloads on other ports or with a bad MBAP
/// header — those stay plain TCP rather than failing the packet.
fn parse_modbus(src_port: Option<u16>, dst_port: Option<u16>, adu: &[u8]) -> Option<ModbusInfo> {
    let is_response = src_port == Some(MODBUS_PORT);
    if !is_response && dst_port != Some(MODBUS_PORT) {
        return None;
    }
    // MBAP header: transaction id (2), protocol id (2, must be 0),
    // length (2, bytes following), unit id (1). Then the PDU.
    if adu.len() < 8 || u16be(adu, 2) != 0 {
        return None;
    }
    let declared = u16be(adu, 4) as usize;
    if declared < 2 || declared + 6 > adu.len() {
        return None;
    }
    let raw_function = adu[7];
    let is_exception = raw_function & 0x80 != 0;
    let function_code = raw_function & 0x7F;
    let mut info = ModbusInfo {
        unit_id: adu[6],
        function_code,
        is_write: !is_response && is_write_function(function_code),
        is_response,
        is_exception,
        address: None,
        quantity: None,
        value: None,
    };
    if !is_response && adu.len() >= 12 {
        // Request PDUs for every function Deadband decodes carry the
        // start address at bytes 8–9; what follows depends on the code.
        info.address = Some(u16be(adu, 8));
        match function_code {
            1 | 2 | 3 | 4 | 15 | 16 => info.quantity = Some(u16be(adu, 10)),
            5 | 6 => info.value = Some(u16be(adu, 10)),
            _ => {}
        }
    }
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim;

    #[test]
    fn empty_packet_is_rejected() {
        let packet = Packet { timestamp_ms: 0, data: Vec::new() };
        assert_eq!(parse_packet(&packet), Err(ParseError::Empty));
    }

    #[test]
    fn truncated_frames_fail_cleanly() {
        for len in [1usize, 10, 20, 40] {
            let packet = Packet { timestamp_ms: 0, data: vec![0u8; len] };
            assert!(parse_packet(&packet).is_err(), "len {len} must not parse");
        }
    }

    #[test]
    fn simulated_read_request_decodes() {
        // One full trip through the simulator's own frame builder: the
        // parser must see exactly the command the plant sent.
        let frame = sim::build_modbus_read(
            "02:db:00:00:00:0a",
            "02:db:00:00:00:11",
            [10, 0, 2, 10],
            [10, 0, 1, 11],
            40000,
            1,
            3,
            100,
            10,
            7,
        );
        let parsed = parse_packet(&Packet { timestamp_ms: 0, data: frame }).unwrap();
        assert_eq!(parsed.protocol, Protocol::ModbusTcp);
        assert_eq!(parsed.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 10))));
        assert_eq!(parsed.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 11))));
        assert_eq!(parsed.dst_port, Some(MODBUS_PORT));
        let mb = parsed.modbus.unwrap();
        assert_eq!(mb.function_code, 3);
        assert!(!mb.is_write);
        assert!(!mb.is_response);
        assert_eq!(mb.address, Some(100));
        assert_eq!(mb.quantity, Some(10));
    }

    #[test]
    fn simulated_write_and_response_decode() {
        let write = sim::build_modbus_write_single(
            "02:db:00:00:00:0a",
            "02:db:00:00:00:11",
            [10, 0, 2, 10],
            [10, 0, 1, 11],
            40000,
            1,
            200,
            425,
            9,
        );
        let parsed = parse_packet(&Packet { timestamp_ms: 0, data: write }).unwrap();
        let mb = parsed.modbus.unwrap();
        assert_eq!(mb.function_code, 6);
        assert!(mb.is_write);
        assert_eq!(mb.address, Some(200));
        assert_eq!(mb.value, Some(425));

        let response = sim::build_modbus_read_response(
            "02:db:00:00:00:11",
            "02:db:00:00:00:0a",
            [10, 0, 1, 11],
            [10, 0, 2, 10],
            40000,
            1,
            3,
            &[101, 102],
            7,
        );
        let parsed = parse_packet(&Packet { timestamp_ms: 0, data: response }).unwrap();
        let mb = parsed.modbus.unwrap();
        assert!(mb.is_response);
        assert!(!mb.is_write);
        assert_eq!(mb.function_code, 3);
    }

    #[test]
    fn plain_tcp_is_classified_not_decoded() {
        let frame = sim::build_tcp_frame(
            "02:db:00:00:00:0a",
            "02:db:00:00:00:20",
            [10, 0, 4, 10],
            [10, 0, 3, 20],
            51000,
            443,
            b"GET / HTTP/1.1\r\n\r\n",
            3,
        );
        let parsed = parse_packet(&Packet { timestamp_ms: 0, data: frame }).unwrap();
        assert_eq!(parsed.protocol, Protocol::Tcp);
        assert_eq!(parsed.modbus, None);
        assert_eq!(parsed.dst_port, Some(443));
    }
}
