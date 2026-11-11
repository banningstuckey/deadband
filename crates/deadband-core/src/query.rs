//! Log query language — a small structured filter over stored events.
//!
//! Grammar (space-separated terms, ANDed together):
//!
//! ```text
//! kind:write | kind:alert | kind:read | kind:discovery
//! kind:connection | kind:packet | kind:analyst
//! src:10.0.1.11 | dst:10.0.1.11 | ip:10.0.1.11   (ip = either side)
//! text:modbus | text:"write single register"     (substring of the summary)
//! last:30m | last:1h | last:24h | last:7d         (relative to now)
//! !term                                            (negation, e.g. !kind:alert, or after the colon: src:!10.0.2.10)
//! bareword                                          (shorthand for text:bareword)
//! ```
//!
//! Kinds are the ones the log shows: `write` is a Modbus write, `read`
//! a Modbus read, the rest map straight onto stored event kinds.
//!
//! The UI shows the query back to the engineer before running it, so a
//! query is always inspectable — including one the local model
//! translated from plain English. The parser rejects unknown fields,
//! unknown kinds, bad IPs and bad durations with a plain-English
//! reason instead of guessing.

use std::net::IpAddr;

use rusqlite::types::Value;

use crate::model::Event;
use crate::store::{Result, Store};

/// One parsed query: every term must match (AND), except negated
/// terms, which must NOT match.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Query {
    /// UI kind names that must match (`write`, `alert`, ...).
    pub kinds: Vec<String>,
    /// UI kind names that must NOT match.
    pub not_kinds: Vec<String>,
    /// (IP, negated) — the event's source must (not) be this IP.
    pub src: Vec<(IpAddr, bool)>,
    /// (IP, negated) — the event's destination must (not) be this IP.
    pub dst: Vec<(IpAddr, bool)>,
    /// (IP, negated) — either side must (not) be this IP.
    pub ip: Vec<(IpAddr, bool)>,
    /// (substring, negated) — the summary must (not) contain this.
    pub text: Vec<(String, bool)>,
    /// Only events at or after this Unix second (from `last:`).
    pub since: Option<i64>,
}

/// Valid `kind:` values, in the order the log's filter chips show them.
pub const QUERY_KINDS: [&str; 7] = [
    "alert", "write", "read", "discovery", "connection", "packet", "analyst",
];

/// Parse a query string. `now_s` is the current Unix second, used to
/// resolve `last:` into an absolute `since`.
pub fn parse(input: &str, now_s: i64) -> std::result::Result<Query, String> {
    let mut query = Query::default();
    for token in split_tokens(input) {
        let (negated, token) = match token.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, token.as_str()),
        };
        if token.is_empty() {
            return Err("a bare '!' needs a term after it".to_string());
        }
        let (field, value) = match token.split_once(':') {
            Some((field, value)) => (Some(field), value),
            None => (None, token),
        };
        // The ! may sit before the field (!kind:alert) or after the
        // colon (src:!10.0.2.10) — both read naturally.
        let (negated, value) = match value.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (negated, value),
        };
        match field {
            None => {
                // Bare word: shorthand for text:word.
                if value.is_empty() {
                    return Err("empty search text".to_string());
                }
                query.text.push((value.to_string(), negated));
            }
            Some("kind") => {
                let kind = normalize_kind(value)?;
                if negated {
                    query.not_kinds.push(kind);
                } else {
                    query.kinds.push(kind);
                }
            }
            Some("src") | Some("dst") | Some("ip") => {
                let ip: IpAddr = value
                    .parse()
                    .map_err(|_| format!("'{value}' is not an IP address — try src:10.0.1.11"))?;
                match field {
                    Some("src") => query.src.push((ip, negated)),
                    Some("dst") => query.dst.push((ip, negated)),
                    _ => query.ip.push((ip, negated)),
                }
            }
            Some("text") => {
                if value.is_empty() {
                    return Err("text: needs something to search for".to_string());
                }
                query.text.push((value.to_string(), negated));
            }
            Some("last") => {
                if negated {
                    return Err("!last: makes no sense — a time window can't be negated".to_string());
                }
                let seconds = parse_duration(value)?;
                query.since = Some(now_s.saturating_sub(seconds));
            }
            Some(other) => {
                return Err(format!(
                    "unknown field '{other}:' — try kind:, src:, dst:, ip:, text:, last:"
                ));
            }
        }
    }
    Ok(query)
}

/// `modbus` is the stored tag name; the log calls it `read`.
fn normalize_kind(value: &str) -> std::result::Result<String, String> {
    let value = if value == "modbus" { "read" } else { value };
    if QUERY_KINDS.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(format!(
            "unknown kind '{value}' — try {}",
            QUERY_KINDS.join(", ")
        ))
    }
}

/// `30m`, `1h`, `24h`, `7d` — a number plus a unit. Caps at 365 days
/// so a typo like `last:9999d` doesn't silently mean "everything".
fn parse_duration(value: &str) -> std::result::Result<i64, String> {
    let (digits, unit) = match value.chars().last() {
        Some(unit @ ('m' | 'h' | 'd')) => (&value[..value.len() - 1], unit),
        _ => {
            return Err(format!(
                "bad window '{value}' — use a number plus m, h or d, e.g. last:1h"
            ))
        }
    };
    let amount: i64 = digits.parse().map_err(|_| {
        format!("bad window '{value}' — use a number plus m, h or d, e.g. last:1h")
    })?;
    if amount <= 0 {
        return Err(format!("bad window '{value}' — the number must be positive"));
    }
    let seconds = match unit {
        'm' => amount.checked_mul(60),
        'h' => amount.checked_mul(3600),
        'd' => amount.checked_mul(86_400),
        _ => unreachable!(),
    };
    let seconds = seconds.filter(|s| *s <= 365 * 86_400).ok_or_else(|| {
        format!("bad window '{value}' — keep it under a year")
    })?;
    Ok(seconds)
}

/// Split on whitespace, keeping `"quoted phrases"` together (the
/// quotes come off; a `"` inside a quoted phrase ends it).
fn split_tokens(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// SQL for one UI kind. Writes are Modbus commands whose summary
/// carries WRITE (storage is lossy — see `kind_from_tag`); reads are
/// the other Modbus commands.
fn kind_condition(kind: &str) -> &'static str {
    match kind {
        "write" => "kind = 'modbus_command' AND instr(summary, 'WRITE') > 0",
        "read" => "kind = 'modbus_command' AND instr(summary, 'WRITE') = 0",
        "alert" => "kind = 'alert_raised'",
        "discovery" => "kind = 'device_discovered'",
        "connection" => "kind = 'connection_observed'",
        "packet" => "kind = 'packet_observed'",
        "analyst" => "kind = 'analyst_note'",
        _ => "1 = 0",
    }
}

/// Escape LIKE wildcards in a user value so `text:100%` searches for
/// a literal percent, not "anything".
fn escape_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

impl Query {
    /// The WHERE clause (without the word WHERE) plus its bound
    /// parameters, in order. Values are always parameters — a query
    /// string never reaches SQL unescaped.
    pub fn to_sql(&self) -> (String, Vec<Value>) {
        let mut clauses: Vec<String> = Vec::new();
        let mut params: Vec<Value> = Vec::new();
        if !self.kinds.is_empty() {
            let ors: Vec<&str> = self.kinds.iter().map(|k| kind_condition(k)).collect();
            clauses.push(format!("({})", ors.join(" OR ")));
        }
        for kind in &self.not_kinds {
            clauses.push(format!("NOT ({})", kind_condition(kind)));
        }
        for (ip, negated) in &self.src {
            params.push(Value::Text(ip.to_string()));
            clauses.push(if *negated {
                "(src_ip IS NULL OR src_ip != ?)".to_string()
            } else {
                "src_ip = ?".to_string()
            });
        }
        for (ip, negated) in &self.dst {
            params.push(Value::Text(ip.to_string()));
            clauses.push(if *negated {
                "(dst_ip IS NULL OR dst_ip != ?)".to_string()
            } else {
                "dst_ip = ?".to_string()
            });
        }
        for (ip, negated) in &self.ip {
            params.push(Value::Text(ip.to_string()));
            params.push(Value::Text(ip.to_string()));
            clauses.push(if *negated {
                "(src_ip IS NULL OR src_ip != ?) AND (dst_ip IS NULL OR dst_ip != ?)".to_string()
            } else {
                "(src_ip = ? OR dst_ip = ?)".to_string()
            });
        }
        for (text, negated) in &self.text {
            params.push(Value::Text(format!("%{}%", escape_like(text))));
            clauses.push(if *negated {
                "summary NOT LIKE ? ESCAPE '\\'".to_string()
            } else {
                "summary LIKE ? ESCAPE '\\'".to_string()
            });
        }
        if let Some(since) = self.since {
            params.push(Value::Integer(since));
            clauses.push("timestamp >= ?".to_string());
        }
        if clauses.is_empty() {
            ("1 = 1".to_string(), params)
        } else {
            (clauses.join(" AND "), params)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EventKind, Event};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn store_with_events() -> Store {
        let store = Store::open_in_memory().unwrap();
        let mut write = Event::new(
            1_700_000_000,
            EventKind::ModbusCommand { function_code: 6, is_write: true },
            "HMI wrote PLC1: WRITE — write single register @ 200 = 420",
        );
        write.src_ip = Some(ip(10, 0, 2, 10));
        write.dst_ip = Some(ip(10, 0, 1, 11));
        store.record_event(&write).unwrap();
        let mut read = Event::new(
            1_700_000_100,
            EventKind::ModbusCommand { function_code: 3, is_write: false },
            "HMI polled PLC2 (read holding registers)",
        );
        read.src_ip = Some(ip(10, 0, 2, 10));
        read.dst_ip = Some(ip(10, 0, 1, 12));
        store.record_event(&read).unwrap();
        let mut alert = Event::new(
            1_700_000_200,
            EventKind::AlertRaised,
            "ALERT: write from non-HMI device",
        );
        alert.src_ip = Some(ip(10, 0, 9, 77));
        alert.dst_ip = Some(ip(10, 0, 1, 11));
        store.record_event(&alert).unwrap();
        let discovery = Event::new(
            1_700_000_300,
            EventKind::DeviceDiscovered,
            "new device 10.0.9.77 seen",
        );
        store.record_event(&discovery).unwrap();
        store
    }

    fn run(store: &Store, text: &str) -> Vec<Event> {
        let query = parse(text, 1_700_000_400).expect("query parses");
        store.query_events(&query, 100).unwrap()
    }

    #[test]
    fn empty_query_returns_everything_newest_first() {
        let store = store_with_events();
        let events = run(&store, "");
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].summary, "new device 10.0.9.77 seen");
    }

    #[test]
    fn kind_write_matches_only_writes() {
        let store = store_with_events();
        let events = run(&store, "kind:write");
        assert_eq!(events.len(), 1);
        assert!(events[0].summary.contains("WRITE"));
    }

    #[test]
    fn kind_read_is_the_other_modbus_direction() {
        let store = store_with_events();
        let events = run(&store, "kind:read");
        assert_eq!(events.len(), 1);
        assert!(events[0].summary.contains("polled"));
    }

    #[test]
    fn dst_and_src_filter_by_ip() {
        let store = store_with_events();
        assert_eq!(run(&store, "dst:10.0.1.11").len(), 2);
        assert_eq!(run(&store, "src:10.0.2.10").len(), 2);
        assert_eq!(run(&store, "ip:10.0.1.12").len(), 1);
        assert_eq!(run(&store, "ip:10.0.9.77").len(), 1);
    }

    #[test]
    fn negation_excludes() {
        let store = store_with_events();
        assert_eq!(run(&store, "src:!10.0.2.10").len(), 2);
        assert_eq!(run(&store, "kind:write src:!10.0.2.10").len(), 0);
        assert_eq!(run(&store, "!kind:alert").len(), 3);
    }

    #[test]
    fn text_search_and_bare_words() {
        let store = store_with_events();
        assert_eq!(run(&store, "text:polled").len(), 1);
        assert_eq!(run(&store, "PLC1").len(), 1);
        assert_eq!(run(&store, "text:\"write single register\"").len(), 1);
        assert_eq!(run(&store, "text:100%").len(), 0);
    }

    #[test]
    fn last_window_is_relative_to_now() {
        let store = store_with_events();
        // now = 1_700_000_400; a 5m window starts at 1_700_000_100.
        assert_eq!(run(&store, "last:5m").len(), 3);
        assert_eq!(run(&store, "last:1h").len(), 4);
    }

    #[test]
    fn combined_terms_and() {
        let store = store_with_events();
        assert_eq!(run(&store, "kind:write dst:10.0.1.11").len(), 1);
        assert_eq!(run(&store, "kind:write dst:10.0.1.12").len(), 0);
    }

    #[test]
    fn parse_errors_name_the_problem() {
        assert!(parse("foo:bar", 0).unwrap_err().contains("unknown field"));
        assert!(parse("kind:nope", 0).unwrap_err().contains("unknown kind"));
        assert!(parse("src:banana", 0).unwrap_err().contains("not an IP address"));
        assert!(parse("last:tomorrow", 0).unwrap_err().contains("bad window"));
        assert!(parse("last:0h", 0).unwrap_err().contains("positive"));
        assert!(parse("!last:1h", 0).unwrap_err().contains("can't be negated"));
        assert!(parse("!", 0).is_err());
        assert!(parse("kind:modbus", 0).is_ok(), "modbus is a read alias");
    }

    #[test]
    fn limit_is_respected() {
        let store = store_with_events();
        let query = parse("", 0).unwrap();
        assert_eq!(store.query_events(&query, 2).unwrap().len(), 2);
    }
}
