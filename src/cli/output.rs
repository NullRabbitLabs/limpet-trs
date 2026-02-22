//! Output formatters for scan results.
//!
//! Supports pretty (nmap-style) and JSON output formats.

use std::net::Ipv4Addr;

use crate::{PortState, ScanResult, ScannedPort};

/// Format a scan result as nmap-style pretty text.
pub fn format_pretty(result: &ScanResult, target_input: &str) -> String {
    let mut out = String::new();

    let version = env!("CARGO_PKG_VERSION");
    out.push_str(&format!(
        "Starting limpet {version} ( https://github.com/nullrabbit/limpet )\n"
    ));

    let host_label = match &result.target_hostname {
        Some(name) => format!("{name} ({})", result.target_ip),
        None => result.target_ip.to_string(),
    };
    out.push_str(&format!("Scan report for {host_label}\n"));

    let duration_s = result.duration_ms as f64 / 1000.0;
    out.push_str(&format!(
        "Host is up ({duration_s:.3}s latency). Backend: {}\n",
        result.backend
    ));
    out.push('\n');

    // Port table
    out.push_str(&format!(
        "{:<10}{:<10}{:<10}{:<6}{}\n",
        "PORT", "STATE", "TIMING", "TTL", "WIN"
    ));

    let mut visible_ports: Vec<&ScannedPort> = result
        .ports
        .iter()
        .filter(|p| p.state != PortState::Pending)
        .collect();
    visible_ports.sort_by_key(|p| p.port);

    for port in &visible_ports {
        let port_label = format!("{}/tcp", port.port);
        let state_label = port.state.to_string();
        let timing_label = if port.timing_ns > 0 {
            format_timing_ns(port.timing_ns)
        } else {
            "-".to_string()
        };
        let ttl_label = if port.had_response() {
            port.response_ttl.to_string()
        } else {
            "-".to_string()
        };
        let win_label = if port.had_response() {
            port.response_win.to_string()
        } else {
            "-".to_string()
        };

        out.push_str(&format!(
            "{:<10}{:<10}{:<10}{:<6}{}\n",
            port_label, state_label, timing_label, ttl_label, win_label
        ));
    }

    out.push('\n');

    let open = result
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .count();
    let closed = result
        .ports
        .iter()
        .filter(|p| p.state == PortState::Closed)
        .count();
    let filtered = result
        .ports
        .iter()
        .filter(|p| p.state == PortState::Filtered)
        .count();
    let firewalled = result
        .ports
        .iter()
        .filter(|p| p.state == PortState::Firewalled)
        .count();
    let unreachable = result
        .ports
        .iter()
        .filter(|p| p.state == PortState::Unreachable)
        .count();

    let total = result.ports.len();
    let duration_s = result.duration_ms as f64 / 1000.0;

    let mut summary_parts = Vec::new();
    if open > 0 {
        summary_parts.push(format!("{open} open"));
    }
    if closed > 0 {
        summary_parts.push(format!("{closed} closed"));
    }
    if filtered > 0 {
        summary_parts.push(format!("{filtered} filtered"));
    }
    if firewalled > 0 {
        summary_parts.push(format!("{firewalled} firewalled"));
    }
    if unreachable > 0 {
        summary_parts.push(format!("{unreachable} unreachable"));
    }

    let summary = if summary_parts.is_empty() {
        "no results".to_string()
    } else {
        summary_parts.join(", ")
    };

    out.push_str(&format!(
        "{total} ports scanned in {duration_s:.2}s ({summary})\n"
    ));

    out
}

/// Format a scan result as JSON.
pub fn format_json(result: &ScanResult) -> String {
    serde_json::to_string_pretty(&JsonOutput::from(result))
        .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"))
}

/// JSON output structure.
#[derive(serde::Serialize)]
struct JsonOutput<'a> {
    target: String,
    hostname: Option<&'a str>,
    backend: &'a str,
    duration_ms: u64,
    ports: Vec<JsonPort<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct JsonPort<'a> {
    port: u16,
    state: &'a str,
    timing_ns: u64,
    ttl: u8,
    win: u16,
}

impl<'a> From<&'a ScanResult> for JsonOutput<'a> {
    fn from(r: &'a ScanResult) -> Self {
        let ports = r
            .ports
            .iter()
            .filter(|p| p.state != PortState::Pending)
            .map(|p| JsonPort {
                port: p.port,
                state: state_str(p.state),
                timing_ns: p.timing_ns,
                ttl: p.response_ttl,
                win: p.response_win,
            })
            .collect();

        Self {
            target: r.target_ip.to_string(),
            hostname: r.target_hostname.as_deref(),
            backend: &r.backend,
            duration_ms: r.duration_ms,
            ports,
            error: r.error.as_deref(),
        }
    }
}

fn state_str(s: PortState) -> &'static str {
    match s {
        PortState::Pending => "pending",
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Unreachable => "unreachable",
        PortState::Filtered => "filtered",
        PortState::Firewalled => "firewalled",
    }
}

/// Format a nanosecond timing value to a human-readable string.
pub fn format_timing_ns(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.1}s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.1}µs", ns as f64 / 1_000.0)
    } else {
        format!("{ns}ns")
    }
}

// Helper for pretty formatter
trait HadResponse {
    fn had_response(&self) -> bool;
}

impl HadResponse for ScannedPort {
    fn had_response(&self) -> bool {
        self.state.had_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PortState, ScanResult, ScannedPort};
    use chrono::Utc;
    use std::net::Ipv4Addr;
    use uuid::Uuid;

    fn make_result(ports: Vec<ScannedPort>) -> ScanResult {
        ScanResult {
            request_id: Uuid::new_v4(),
            target_ip: Ipv4Addr::new(1, 2, 3, 4),
            target_hostname: None,
            ports,
            duration_ms: 3420,
            backend: "xdp".to_string(),
            scanned_at: Utc::now(),
            error: None,
        }
    }

    #[test]
    fn test_format_timing_ns_nanoseconds() {
        assert_eq!(format_timing_ns(500), "500ns");
    }

    #[test]
    fn test_format_timing_ns_microseconds() {
        assert_eq!(format_timing_ns(1_500), "1.5µs");
    }

    #[test]
    fn test_format_timing_ns_milliseconds() {
        assert_eq!(format_timing_ns(1_200_000), "1.2ms");
    }

    #[test]
    fn test_format_timing_ns_seconds() {
        assert_eq!(format_timing_ns(1_500_000_000), "1.5s");
    }

    #[test]
    fn test_format_pretty_header() {
        let result = make_result(vec![]);
        let output = format_pretty(&result, "1.2.3.4");
        assert!(output.contains("Starting limpet"));
        assert!(output.contains("Scan report for 1.2.3.4"));
        assert!(output.contains("Backend: xdp"));
    }

    #[test]
    fn test_format_pretty_open_port() {
        let result = make_result(vec![ScannedPort {
            port: 80,
            state: PortState::Open,
            timing_ns: 800_000,
            response_ttl: 64,
            response_win: 65535,
        }]);
        let output = format_pretty(&result, "1.2.3.4");
        assert!(output.contains("80/tcp"));
        assert!(output.contains("open"));
        assert!(output.contains("64"));
    }

    #[test]
    fn test_format_pretty_filtered_port_shows_dashes() {
        let result = make_result(vec![ScannedPort {
            port: 8080,
            state: PortState::Filtered,
            timing_ns: 0,
            response_ttl: 0,
            response_win: 0,
        }]);
        let output = format_pretty(&result, "1.2.3.4");
        assert!(output.contains("filtered"));
        // TTL and WIN should be dashes for filtered
        assert!(output.contains("-"));
    }

    #[test]
    fn test_format_pretty_summary() {
        let result = make_result(vec![
            ScannedPort {
                port: 22,
                state: PortState::Open,
                timing_ns: 1_000_000,
                response_ttl: 64,
                response_win: 65535,
            },
            ScannedPort {
                port: 80,
                state: PortState::Open,
                timing_ns: 800_000,
                response_ttl: 64,
                response_win: 65535,
            },
            ScannedPort {
                port: 8080,
                state: PortState::Filtered,
                timing_ns: 0,
                response_ttl: 0,
                response_win: 0,
            },
        ]);
        let output = format_pretty(&result, "1.2.3.4");
        assert!(output.contains("3 ports scanned"));
        assert!(output.contains("2 open"));
        assert!(output.contains("1 filtered"));
    }

    #[test]
    fn test_format_json_structure() {
        let result = make_result(vec![ScannedPort {
            port: 443,
            state: PortState::Open,
            timing_ns: 900_000,
            response_ttl: 64,
            response_win: 65535,
        }]);
        let json = format_json(&result);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["target"], "1.2.3.4");
        assert_eq!(parsed["backend"], "xdp");
        assert_eq!(parsed["duration_ms"], 3420);
        assert_eq!(parsed["ports"][0]["port"], 443);
        assert_eq!(parsed["ports"][0]["state"], "open");
    }

    #[test]
    fn test_format_json_pending_ports_excluded() {
        let result = make_result(vec![
            ScannedPort {
                port: 80,
                state: PortState::Open,
                timing_ns: 0,
                response_ttl: 0,
                response_win: 0,
            },
            ScannedPort {
                port: 81,
                state: PortState::Pending,
                timing_ns: 0,
                response_ttl: 0,
                response_win: 0,
            },
        ]);
        let json = format_json(&result);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ports"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["ports"][0]["port"], 80);
    }

    #[test]
    fn test_format_json_hostname() {
        let mut result = make_result(vec![]);
        result.target_hostname = Some("example.com".to_string());
        let json = format_json(&result);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["hostname"], "example.com");
    }
}
