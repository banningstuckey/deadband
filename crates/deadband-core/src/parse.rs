//! Packet parsing: raw bytes in, structured facts out.
//!
//! Phase 0 defines the *shape* of parsing — the input ([`Packet`]), the
//! output ([`ParsedPacket`]), and the error type — but implements no
//! protocol decoding yet:
//!
//! - Phase 1 implements Ethernet/IP/TCP/UDP basics and Modbus/TCP.
//! - Phase 3 hardens the same code against real-world captures.
//!
//! Parsing is a pure function of the packet bytes. It performs no I/O
//! and — per the project's safety rules — never crafts response packets.
//! Real plant traffic is untrusted input: parsers here must treat every
//! length field as a lie until checked, and must never panic on garbage.

use crate::model::Protocol;
use crate::source::Packet;
use std::fmt;
use std::net::IpAddr;

/// The Modbus facts lifted out of a Modbus/TCP packet — the fields
/// detection actually reasons about. (Full register values are process
/// data; a security monitor mostly needs *who commanded what, how*.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModbusInfo {
    /// Modbus unit/slave id the command addresses.
    pub unit_id: u8,
    /// Function code (1–4 reads, 5/6/15/16 writes, …).
    pub function_code: u8,
    /// True when the function code changes state on the target
    /// (write coil/register, etc.) — writes from unexpected sources are
    /// among the highest-signal events in OT monitoring.
    pub is_write: bool,
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

/// Parses one raw packet into a [`ParsedPacket`].
///
/// Phase 0 stub: recognises only the empty packet. Phase 1 implements
/// Ethernet → IPv4/IPv6 → TCP/UDP → Modbus/TCP decoding.
pub fn parse_packet(packet: &Packet) -> Result<ParsedPacket, ParseError> {
    if packet.data.is_empty() {
        return Err(ParseError::Empty);
    }
    Err(ParseError::NotImplemented("ethernet/ip parsing (Phase 1)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_packet_is_rejected() {
        let packet = Packet { timestamp_ms: 0, data: Vec::new() };
        assert_eq!(parse_packet(&packet), Err(ParseError::Empty));
    }

    #[test]
    fn real_decoding_is_a_phase_1_stub() {
        let packet = Packet { timestamp_ms: 0, data: vec![0u8; 64] };
        assert_eq!(
            parse_packet(&packet),
            Err(ParseError::NotImplemented("ethernet/ip parsing (Phase 1)"))
        );
    }
}
