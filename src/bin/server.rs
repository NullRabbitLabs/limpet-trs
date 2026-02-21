//! limpet-server — HTTP service wrapping the limpet scan engine.
//!
//! Exposes limpet's XDP port discovery and BPF timing collection over HTTP so
//! the orchestrator can call it directly instead of via Redis streams. This
//! replaces limpet-timing (the Rust Redis consumer service).
//!
//! ## API
//!
//! ```text
//! POST /v1/discovery   — XDP port discovery scan
//! POST /v1/timing      — BPF TCP RTT timing collection
//! GET  /v1/health      — health / worker info
//! ```
//!
//! ## Environment variables
//!
//! | Variable           | Default    | Description                          |
//! |--------------------|------------|--------------------------------------|
//! | `PORT`             | `8888`     | HTTP listen port                     |
//! | `LIMPET_INTERFACE` | auto       | Network interface for XDP            |
//! | `WORKER_NODE`      | hostname   | Worker node name reported in results |

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use limpet::{PortSpec, PortState, ScanResult, ScannedPort, TimingRequest};
use limpet::scanner::collector::DiscoveryCollector;
use limpet::scanner::stealth::{PacingProfile, StealthProfile};
use limpet::scanner::syn_sender::{detect_source_ip, SynScanner};
use limpet::timing::collect_timing_samples;

// ─────────────────────────────────────────────────────────────────────────────
// Shared server state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ServerState {
    worker_node: String,
    interface: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire types — must match the orchestrator's domain.DiscoveryRequestMessage /
// domain.DiscoveryResultMessage / domain.TimingRequestMessage /
// domain.TimingResultMessage JSON format exactly.
// ─────────────────────────────────────────────────────────────────────────────

/// Port spec from the orchestrator. The server only accepts "Explicit",
/// "Range", and "Full" — the orchestrator always expands "Common"/"CommonPlus"
/// before sending since it knows the list.
#[derive(Debug, Deserialize)]
struct PortSpecWire {
    #[serde(rename = "type")]
    kind: String,
    value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct DiscoveryRequest {
    request_id: String,
    scan_id: Option<String>,
    target_ip: String,
    target_hostname: Option<String>,
    ports: PortSpecWire,
    timeout_ms: u64,
    #[serde(default)]
    sample_count: u32,
    pacing_profile: Option<String>,
    #[serde(default)]
    max_ports: Option<u32>,
    // Shard metadata (flat in the JSON object)
    #[serde(default)]
    base_request_id: Option<String>,
    #[serde(default)]
    shard_index: u32,
    #[serde(default)]
    total_shards: u32,
}

#[derive(Debug, Serialize)]
struct DiscoveredPort {
    port: u16,
    state: PortState,
    timing_ns: u64,
    response_ttl: u8,
    response_win: u16,
}

#[derive(Debug, Serialize)]
struct DiscoveryResult {
    request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_id: Option<String>,
    target_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_hostname: Option<String>,
    ports_scanned: u32,
    port_results: Vec<DiscoveredPort>,
    estimated_duration_ms: u64,
    actual_duration_ms: u64,
    scanner_backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worker_node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_request_id: Option<String>,
    shard_index: u32,
    total_shards: u32,
}

#[derive(Debug, Serialize)]
struct HealthInfo {
    status: &'static str,
    worker_node: String,
    source_ip: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Port spec conversion
// ─────────────────────────────────────────────────────────────────────────────

fn wire_to_port_spec(spec: &PortSpecWire) -> Result<PortSpec, String> {
    match spec.kind.as_str() {
        "Explicit" => {
            let ports = match &spec.value {
                Some(serde_json::Value::Array(arr)) => {
                    arr.iter()
                        .map(|v| {
                            v.as_u64()
                                .and_then(|n| u16::try_from(n).ok())
                                .ok_or_else(|| format!("invalid port in Explicit spec: {v}"))
                        })
                        .collect::<Result<Vec<u16>, _>>()?
                }
                _ => return Err("Explicit port spec requires array value".to_string()),
            };
            Ok(PortSpec::Explicit(ports))
        }
        "Range" => {
            let obj = spec
                .value
                .as_ref()
                .and_then(|v| v.as_object())
                .ok_or("Range spec requires object value with start/end")?;
            let start = obj
                .get("start")
                .and_then(|v| v.as_u64())
                .and_then(|n| u16::try_from(n).ok())
                .ok_or("Range spec missing valid 'start'")?;
            let end = obj
                .get("end")
                .and_then(|v| v.as_u64())
                .and_then(|n| u16::try_from(n).ok())
                .ok_or("Range spec missing valid 'end'")?;
            Ok(PortSpec::Range { start, end })
        }
        "Full" => Ok(PortSpec::Full),
        other => Err(format!(
            "unsupported port spec type '{other}'; orchestrator must expand Common/CommonPlus before sending"
        )),
    }
}

fn pacing_from_str(s: &str) -> PacingProfile {
    match s.to_lowercase().as_str() {
        "aggressive" => PacingProfile::Aggressive,
        "stealthy" | "stealth" => PacingProfile::Stealthy,
        "paranoid" => PacingProfile::Paranoid,
        _ => PacingProfile::Normal,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn handle_discovery(
    State(state): State<ServerState>,
    Json(req): Json<DiscoveryRequest>,
) -> impl IntoResponse {
    let start = Instant::now();

    let port_spec = match wire_to_port_spec(&req.ports) {
        Ok(s) => s,
        Err(e) => {
            let result = DiscoveryResult {
                request_id: req.request_id,
                scan_id: req.scan_id,
                target_ip: req.target_ip,
                target_hostname: req.target_hostname,
                ports_scanned: 0,
                port_results: vec![],
                estimated_duration_ms: 0,
                actual_duration_ms: 0,
                scanner_backend: "error".to_string(),
                error: Some(format!("invalid port spec: {e}")),
                source_ip: None,
                worker_node: Some(state.worker_node),
                base_request_id: req.base_request_id,
                shard_index: req.shard_index,
                total_shards: req.total_shards,
            };
            return (StatusCode::OK, Json(result));
        }
    };

    let pacing = req
        .pacing_profile
        .as_deref()
        .map(pacing_from_str)
        .unwrap_or(PacingProfile::Normal);

    match run_discovery(
        &req.target_ip,
        port_spec,
        pacing,
        req.timeout_ms as u32,
        req.max_ports,
        &state.interface,
    )
    .await
    {
        Ok(scan_result) => {
            let actual_ms = start.elapsed().as_millis() as u64;
            let source_ip = scan_result.target_ip.to_string();

            let port_results: Vec<DiscoveredPort> = scan_result
                .ports
                .into_iter()
                .map(|p| DiscoveredPort {
                    port: p.port,
                    state: p.state,
                    timing_ns: p.timing_ns,
                    response_ttl: p.response_ttl,
                    response_win: p.response_win,
                })
                .collect();

            let ports_scanned = port_results.len() as u32;

            let result = DiscoveryResult {
                request_id: req.request_id,
                scan_id: req.scan_id,
                target_ip: req.target_ip,
                target_hostname: req.target_hostname
                    .or_else(|| scan_result.target_hostname),
                ports_scanned,
                port_results,
                estimated_duration_ms: scan_result.duration_ms,
                actual_duration_ms: actual_ms,
                scanner_backend: scan_result.backend,
                error: scan_result.error,
                source_ip: Some(source_ip),
                worker_node: Some(state.worker_node),
                base_request_id: req.base_request_id,
                shard_index: req.shard_index,
                total_shards: req.total_shards,
            };
            (StatusCode::OK, Json(result))
        }
        Err(e) => {
            let actual_ms = start.elapsed().as_millis() as u64;
            let result = DiscoveryResult {
                request_id: req.request_id,
                scan_id: req.scan_id,
                target_ip: req.target_ip,
                target_hostname: req.target_hostname,
                ports_scanned: 0,
                port_results: vec![],
                estimated_duration_ms: 0,
                actual_duration_ms: actual_ms,
                scanner_backend: "unavailable".to_string(),
                error: Some(e),
                source_ip: None,
                worker_node: Some(state.worker_node),
                base_request_id: req.base_request_id,
                shard_index: req.shard_index,
                total_shards: req.total_shards,
            };
            (StatusCode::OK, Json(result))
        }
    }
}

async fn handle_timing(
    State(state): State<ServerState>,
    Json(req): Json<TimingRequest>,
) -> impl IntoResponse {
    // Initialise BPF timing backend (best-effort; falls back to userspace)
    let bpf = match limpet::detect_timing_backend(&state.interface) {
        Ok((_, collector)) => Some(Arc::new(Mutex::new(collector))),
        Err(e) => {
            tracing::warn!(error = %e, "BPF backend unavailable for timing, using userspace fallback");
            None
        }
    };

    let result = collect_timing_samples(&req, bpf).await;
    (StatusCode::OK, Json(result))
}

async fn handle_health(State(state): State<ServerState>) -> impl IntoResponse {
    let source_ip = detect_own_ip();
    Json(HealthInfo {
        status: "ok",
        worker_node: state.worker_node,
        source_ip,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan engine (mirrors cli::run_scan but without CLI arg parsing)
// ─────────────────────────────────────────────────────────────────────────────

async fn run_discovery(
    target: &str,
    port_spec: PortSpec,
    pacing: PacingProfile,
    timeout_ms: u32,
    max_ports: Option<u32>,
    interface: &Option<String>,
) -> Result<ScanResult, String> {
    let start = Instant::now();

    // Resolve target
    let target_ip: Ipv4Addr = if let Ok(ip) = target.parse::<Ipv4Addr>() {
        ip
    } else {
        use std::net::ToSocketAddrs;
        let addrs = format!("{target}:0")
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed: {e}"))?;
        addrs
            .filter_map(|a| match a.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .next()
            .ok_or_else(|| format!("no IPv4 address found for '{target}'"))?
    };
    let target_hostname = if target.parse::<Ipv4Addr>().is_err() {
        Some(target.to_string())
    } else {
        None
    };

    let request_id = Uuid::new_v4();

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target_ip, port_spec, pacing, timeout_ms, max_ports, interface, request_id);
        return Err("XDP scanning requires Linux with CAP_BPF and CAP_NET_ADMIN".to_string());
    }

    #[cfg(target_os = "linux")]
    {
        use limpet::scanner::afxdp_sender::{AfXdpSend, AfXdpSender};
        use limpet::scanner::raw_socket_sender::RawSocketSender;

        let (backend, bpf_collector) = limpet::detect_timing_backend(interface)
            .map_err(|e| format!("BPF initialisation failed: {e}"))?;

        let backend_str = backend.as_str().to_string();
        let iface = bpf_collector.interface().to_string();
        let bpf = Arc::new(Mutex::new(bpf_collector));

        let src_ip = detect_source_ip(target_ip)
            .map_err(|e| format!("source IP detection failed: {e}"))?;

        let mut stealth = StealthProfile::linux_6x_default();
        pacing.apply_to(&mut stealth);

        let mut ports = port_spec.expand();
        if let Some(max) = max_ports {
            ports.truncate(max as usize);
        }
        let batch_size = pacing.batch_size();
        let timeout = Duration::from_millis(timeout_ms as u64);

        let xdp_sender: Box<dyn AfXdpSend> = match AfXdpSender::new(&iface, 0, src_ip) {
            Ok(sender) => {
                let bpf_guard = bpf.lock().await;
                if let Err(e) = bpf_guard.register_xsk_fd(sender.fd()) {
                    tracing::warn!(error = %e, "xsk_map registration failed");
                }
                drop(bpf_guard);
                Box::new(sender)
            }
            Err(e) => {
                tracing::warn!(error = %e, "AF_XDP unavailable — falling back to raw socket TX");
                Box::new(
                    RawSocketSender::new(src_ip)
                        .map_err(|e| format!("raw socket fallback failed: {e}"))?,
                )
            }
        };

        let mut scanner = SynScanner::new_with_sender(stealth, xdp_sender);
        let collector = DiscoveryCollector::new(timeout);
        let target_ip_u32 = u32::from_be_bytes(target_ip.octets());

        let mut all_probes = Vec::new();
        for batch in ports.chunks(batch_size) {
            let result = scanner
                .send_syn_batch(target_ip, batch)
                .map_err(|e| format!("scan error: {e}"))?;
            all_probes.extend(result.probed_ports);
        }

        tokio::time::sleep(Duration::from_millis(timeout_ms as u64)).await;

        let bpf_guard = bpf.lock().await;
        let discovery = collector.collect(&all_probes, &*bpf_guard, target_ip_u32);
        drop(bpf_guard);

        let scanned_ports: Vec<ScannedPort> = discovery
            .ports
            .into_iter()
            .map(|p| ScannedPort {
                port: p.port,
                state: p.state,
                timing_ns: p.timing_ns,
                response_ttl: p.response_ttl,
                response_win: p.response_win,
            })
            .collect();

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ScanResult {
            request_id,
            target_ip,
            target_hostname,
            ports: scanned_ports,
            duration_ms,
            backend: backend_str,
            scanned_at: Utc::now(),
            error: None,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn detect_own_ip() -> Option<String> {
    // Use a dummy UDP connect to find the outbound interface IP
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn default_worker_node() -> String {
    std::env::var("WORKER_NODE")
        .ok()
        .unwrap_or_else(|| {
            nix::unistd::gethostname()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| format!("limpet-{}", std::process::id()))
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8888);

    let interface = std::env::var("LIMPET_INTERFACE").ok();
    let worker_node = default_worker_node();

    tracing::info!(worker_node = %worker_node, port = port, "limpet-server starting");

    let state = ServerState {
        worker_node,
        interface,
    };

    let app = Router::new()
        .route("/v1/discovery", post(handle_discovery))
        .route("/v1/timing", post(handle_timing))
        .route("/v1/health", get(handle_health))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind to {addr}: {e}"));

    tracing::info!(addr = %addr, "limpet-server listening");

    axum::serve(listener, app)
        .await
        .expect("server error");
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_to_port_spec_explicit() {
        let spec = PortSpecWire {
            kind: "Explicit".to_string(),
            value: Some(serde_json::json!([80, 443, 8080])),
        };
        let result = wire_to_port_spec(&spec).unwrap();
        assert_eq!(result, PortSpec::Explicit(vec![80, 443, 8080]));
    }

    #[test]
    fn test_wire_to_port_spec_range() {
        let spec = PortSpecWire {
            kind: "Range".to_string(),
            value: Some(serde_json::json!({"start": 1, "end": 1024})),
        };
        let result = wire_to_port_spec(&spec).unwrap();
        assert_eq!(result, PortSpec::Range { start: 1, end: 1024 });
    }

    #[test]
    fn test_wire_to_port_spec_full() {
        let spec = PortSpecWire {
            kind: "Full".to_string(),
            value: None,
        };
        let result = wire_to_port_spec(&spec).unwrap();
        assert_eq!(result, PortSpec::Full);
    }

    #[test]
    fn test_wire_to_port_spec_rejects_common() {
        let spec = PortSpecWire {
            kind: "Common".to_string(),
            value: None,
        };
        assert!(wire_to_port_spec(&spec).is_err());
    }

    #[test]
    fn test_pacing_from_str() {
        assert_eq!(pacing_from_str("aggressive"), PacingProfile::Aggressive);
        assert_eq!(pacing_from_str("stealthy"), PacingProfile::Stealthy);
        assert_eq!(pacing_from_str("paranoid"), PacingProfile::Paranoid);
        assert_eq!(pacing_from_str("normal"), PacingProfile::Normal);
        assert_eq!(pacing_from_str("unknown"), PacingProfile::Normal);
    }

    #[test]
    fn test_explicit_port_spec_invalid_port() {
        let spec = PortSpecWire {
            kind: "Explicit".to_string(),
            value: Some(serde_json::json!([99999])),
        };
        assert!(wire_to_port_spec(&spec).is_err());
    }
}
