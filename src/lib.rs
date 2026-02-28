//! Limpet — high-precision network scanner with eBPF/XDP kernel-bypass timing.
//!
//! Provides SYN-based port discovery with nanosecond RTT measurement and
//! ML-ready feature extraction. Usable as a library or via the CLI.

pub mod cli;
pub mod engine;
pub mod scanner;
pub mod timing;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use uuid::Uuid;

// Re-export key backend types for library users.
pub use engine::{Engine, ScanEngineConfig};
pub use scanner::stealth::{PacingProfile, StealthProfile};
pub use scanner::syn_sender::ScanError;
pub use timing::detect_timing_backend;
pub use timing::xdp::{BpfTimingCollector, BpfTimingError, MockBpfTimingCollector};

// ─────────────────────────────────────────────────────────────────────────────
// Port state
// ─────────────────────────────────────────────────────────────────────────────

/// Port discovery state from BPF map.
///
/// Matches the `port_state` field in the BPF `timing_value` struct.
/// Values 0-3 are set by BPF programs; value 4 (Filtered) is promoted
/// in userspace when a Pending entry times out. Value 5 (Firewalled) is
/// promoted in userspace when a Closed (RST) port exhibits firewall
/// fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PortState {
    /// SYN sent, no response yet.
    Pending = 0,
    /// SYN-ACK received — port is open.
    Open = 1,
    /// RST received — port is closed (real host responded).
    Closed = 2,
    /// ICMP unreachable received.
    Unreachable = 3,
    /// No response after timeout (promoted from Pending in userspace).
    Filtered = 4,
    /// RST received but fingerprinted as a firewall/middlebox response.
    Firewalled = 5,
}

impl PortState {
    /// Convert a raw u8 to PortState, defaulting to Pending for unknown values.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Pending,
            1 => Self::Open,
            2 => Self::Closed,
            3 => Self::Unreachable,
            4 => Self::Filtered,
            5 => Self::Firewalled,
            _ => Self::Pending,
        }
    }

    /// Returns true if the port had any response (open, closed, unreachable, firewalled).
    pub fn had_response(&self) -> bool {
        matches!(
            self,
            Self::Open | Self::Closed | Self::Unreachable | Self::Firewalled
        )
    }
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Open => write!(f, "open"),
            Self::Closed => write!(f, "closed"),
            Self::Unreachable => write!(f, "unreachable"),
            Self::Filtered => write!(f, "filtered"),
            Self::Firewalled => write!(f, "firewalled"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Timing backend
// ─────────────────────────────────────────────────────────────────────────────

/// Timing collection backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TimingBackend {
    /// TC egress + XDP ingress (full kernel timestamps).
    #[default]
    Xdp,
    /// Userspace SYN + XDP SYN-ACK (hybrid mode, TC attach failed).
    XdpHybrid,
}

impl TimingBackend {
    /// String identifier for this backend.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Xdp => "xdp",
            Self::XdpHybrid => "xdp-hybrid",
        }
    }

    /// Get the precision class string for this backend.
    pub fn precision_class(&self) -> &'static str {
        match self {
            Self::Xdp | Self::XdpHybrid => "xdp",
        }
    }
}

impl std::fmt::Display for TimingBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Port specification (parsed from CLI or MCP)
// ─────────────────────────────────────────────────────────────────────────────

/// Port specification — can be a single port, a range, or a comma-separated list.
///
/// Parsed from strings like "80", "1-1024", "80,443,8080".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PortSpec {
    /// Explicit list of ports.
    Explicit(Vec<u16>),
    /// Contiguous port range (inclusive).
    Range { start: u16, end: u16 },
    /// Full range 1-65535.
    Full,
}

impl PortSpec {
    /// Parse a port spec string ("80", "1-1024", "80,443,8080", "1-65535").
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s == "1-65535" || s == "full" {
            return Ok(Self::Full);
        }
        if s.contains('-') && !s.contains(',') {
            let parts: Vec<&str> = s.splitn(2, '-').collect();
            if parts.len() == 2 {
                let start = parts[0]
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port range start: '{}'", parts[0]))?;
                let end = parts[1]
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port range end: '{}'", parts[1]))?;
                if end < start {
                    return Err(format!("invalid range: {} > {}", start, end));
                }
                return Ok(Self::Range { start, end });
            }
        }
        // Comma-separated list or single port
        let ports: Result<Vec<u16>, _> = s
            .split(',')
            .map(|p| {
                p.trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port: '{}'", p.trim()))
            })
            .collect();
        Ok(Self::Explicit(ports?))
    }

    /// Expand to a sorted, deduplicated list of port numbers.
    pub fn expand(&self) -> Vec<u16> {
        match self {
            Self::Explicit(ports) => {
                let mut v = ports.clone();
                v.sort_unstable();
                v.dedup();
                v
            }
            Self::Range { start, end } => (*start..=*end).collect(),
            Self::Full => (1..=65535).collect(),
        }
    }

    /// Return the count of ports this spec covers.
    pub fn count(&self) -> usize {
        match self {
            Self::Explicit(ports) => ports.len(),
            Self::Range { start, end } => (*end as usize - *start as usize) + 1,
            Self::Full => 65535,
        }
    }
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Explicit(ports) => {
                let s: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                write!(f, "{}", s.join(","))
            }
            Self::Range { start, end } => write!(f, "{}-{}", start, end),
            Self::Full => write!(f, "1-65535"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Clean scan request / result types (no Redis/DB fields)
// ─────────────────────────────────────────────────────────────────────────────

/// Request to scan a target host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Unique identifier for this scan request.
    pub request_id: Uuid,
    /// Target IP address or hostname (tool resolves DNS).
    pub target: String,
    /// Port specification.
    pub ports: PortSpec,
    /// Pacing profile controlling scan speed.
    pub pacing: PacingProfile,
    /// Per-port response timeout in milliseconds.
    pub timeout_ms: u32,
    /// Network interface for XDP (None = auto-detect).
    pub interface: Option<String>,
    /// Maximum number of ports to scan (truncates expanded port list).
    #[serde(default)]
    pub max_ports: Option<u32>,
}

/// Result of a port scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique identifier matching the request.
    pub request_id: Uuid,
    /// Resolved target IP address.
    pub target_ip: Ipv4Addr,
    /// Original hostname if DNS was resolved.
    pub target_hostname: Option<String>,
    /// Per-port scan results.
    pub ports: Vec<ScannedPort>,
    /// Total scan duration in milliseconds.
    pub duration_ms: u64,
    /// Backend used for this scan.
    pub backend: String,
    /// Timestamp when the scan completed.
    pub scanned_at: DateTime<Utc>,
    /// Error message if the scan failed.
    pub error: Option<String>,
}

/// Result for a single scanned port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedPort {
    /// Port number.
    pub port: u16,
    /// Port state.
    pub state: PortState,
    /// SYN-to-response timing in nanoseconds (0 if no response).
    pub timing_ns: u64,
    /// IP TTL from response (0 if no response).
    pub response_ttl: u8,
    /// TCP window from response (0 if no response).
    pub response_win: u16,
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy timing types (kept for backward compatibility with timing module)
// ─────────────────────────────────────────────────────────────────────────────

mod base64_opt_bytes {
    use base64::Engine;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(b);
                serializer.serialize_str(&encoded)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => base64::engine::general_purpose::STANDARD
                .decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Request for timing collection on a target host:port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingRequest {
    /// Unique identifier for this timing request.
    pub request_id: Uuid,
    /// Associated scan ID, if part of a scan workflow.
    pub scan_id: Option<Uuid>,
    /// Target hostname or IP address.
    pub target_host: String,
    /// Target port number.
    pub target_port: u16,
    /// Number of timing samples to collect.
    pub sample_count: u32,
    /// Connection timeout in milliseconds.
    pub timeout_ms: u32,
    /// Read timeout for passive banner capture on the last sample (ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner_timeout_ms: Option<u32>,
}

/// Result of timing collection containing samples and statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingResult {
    /// Matches the request_id from TimingRequest.
    pub request_id: Uuid,
    /// Associated scan ID, if part of a scan workflow.
    pub scan_id: Option<Uuid>,
    /// Target hostname or IP address.
    pub target_host: String,
    /// Target port number.
    pub target_port: u16,
    /// Collected timing samples in microseconds.
    pub samples: Vec<f64>,
    /// Classification of timing precision (e.g., "xdp", "userspace").
    pub precision_class: String,
    /// Statistical summary of the timing samples.
    pub stats: TimingStats,
    /// Timestamp when samples were collected.
    pub collected_at: DateTime<Utc>,
    /// Error message if collection failed.
    pub error: Option<String>,
    /// NTE embedding vector (64-dim, L2-normalized).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f64>>,
    /// Passive banner bytes captured on the last timing sample.
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "base64_opt_bytes"
    )]
    pub banner: Option<Vec<u8>>,
    /// Source IP used for timing probes (populated by server, not collector).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// Worker node hostname (populated by server, not collector).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_node: Option<String>,
}

/// Statistical summary of timing samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingStats {
    /// Mean (average) timing in microseconds.
    pub mean: f64,
    /// Standard deviation in microseconds.
    pub std: f64,
    /// 50th percentile (median) in microseconds.
    pub p50: f64,
    /// 90th percentile in microseconds.
    pub p90: f64,
}

impl TimingStats {
    /// Creates an empty TimingStats with all zeros.
    pub fn empty() -> Self {
        Self {
            mean: 0.0,
            std: 0.0,
            p50: 0.0,
            p90: 0.0,
        }
    }
}

impl TimingResult {
    /// Creates an error result for failed timing collection.
    pub fn error(request: &TimingRequest, error: String) -> Self {
        Self {
            request_id: request.request_id,
            scan_id: request.scan_id,
            target_host: request.target_host.clone(),
            target_port: request.target_port,
            samples: vec![],
            precision_class: "error".to_string(),
            stats: TimingStats::empty(),
            collected_at: Utc::now(),
            error: Some(error),
            embedding: None,
            banner: None,
            source_ip: None,
            worker_node: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_state_values() {
        assert_eq!(PortState::Pending as u8, 0);
        assert_eq!(PortState::Open as u8, 1);
        assert_eq!(PortState::Closed as u8, 2);
        assert_eq!(PortState::Unreachable as u8, 3);
        assert_eq!(PortState::Filtered as u8, 4);
        assert_eq!(PortState::Firewalled as u8, 5);
    }

    #[test]
    fn test_port_state_from_u8_roundtrip() {
        assert_eq!(PortState::from_u8(0), PortState::Pending);
        assert_eq!(PortState::from_u8(1), PortState::Open);
        assert_eq!(PortState::from_u8(2), PortState::Closed);
        assert_eq!(PortState::from_u8(3), PortState::Unreachable);
        assert_eq!(PortState::from_u8(4), PortState::Filtered);
        assert_eq!(PortState::from_u8(5), PortState::Firewalled);
        assert_eq!(PortState::from_u8(255), PortState::Pending);
    }

    #[test]
    fn test_port_state_had_response() {
        assert!(!PortState::Pending.had_response());
        assert!(PortState::Open.had_response());
        assert!(PortState::Closed.had_response());
        assert!(PortState::Unreachable.had_response());
        assert!(!PortState::Filtered.had_response());
        assert!(PortState::Firewalled.had_response());
    }

    #[test]
    fn test_port_state_display() {
        assert_eq!(PortState::Open.to_string(), "open");
        assert_eq!(PortState::Filtered.to_string(), "filtered");
        assert_eq!(PortState::Firewalled.to_string(), "firewalled");
    }

    #[test]
    fn test_timing_backend_as_str() {
        assert_eq!(TimingBackend::Xdp.as_str(), "xdp");
        assert_eq!(TimingBackend::XdpHybrid.as_str(), "xdp-hybrid");
    }

    #[test]
    fn test_port_spec_parse_single() {
        let spec = PortSpec::parse("80").unwrap();
        assert_eq!(spec, PortSpec::Explicit(vec![80]));
    }

    #[test]
    fn test_port_spec_parse_range() {
        let spec = PortSpec::parse("1-1024").unwrap();
        assert_eq!(
            spec,
            PortSpec::Range {
                start: 1,
                end: 1024
            }
        );
    }

    #[test]
    fn test_port_spec_parse_list() {
        let spec = PortSpec::parse("80,443,8080").unwrap();
        assert_eq!(spec, PortSpec::Explicit(vec![80, 443, 8080]));
    }

    #[test]
    fn test_port_spec_parse_full() {
        let spec = PortSpec::parse("1-65535").unwrap();
        assert_eq!(spec, PortSpec::Full);
    }

    #[test]
    fn test_port_spec_expand_range() {
        let spec = PortSpec::Range { start: 1, end: 5 };
        assert_eq!(spec.expand(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_port_spec_count() {
        assert_eq!(PortSpec::Range { start: 1, end: 100 }.count(), 100);
        assert_eq!(PortSpec::Full.count(), 65535);
        assert_eq!(PortSpec::Explicit(vec![80, 443]).count(), 2);
    }

    #[test]
    fn test_port_spec_parse_invalid_range() {
        assert!(PortSpec::parse("1024-1").is_err());
    }

    #[test]
    fn test_timing_stats_empty() {
        let stats = TimingStats::empty();
        assert_eq!(stats.mean, 0.0);
        assert_eq!(stats.std, 0.0);
        assert_eq!(stats.p50, 0.0);
        assert_eq!(stats.p90, 0.0);
    }

    #[test]
    fn test_port_spec_display() {
        assert_eq!(
            PortSpec::Range {
                start: 1,
                end: 1024
            }
            .to_string(),
            "1-1024"
        );
        assert_eq!(PortSpec::Full.to_string(), "1-65535");
        assert_eq!(PortSpec::Explicit(vec![80, 443]).to_string(), "80,443");
    }
}
