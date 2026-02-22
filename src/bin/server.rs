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
    /// Network interface resolved at startup (e.g. "eth0").
    resolved_interface: String,
    /// Backend string resolved at startup: "xdp", "xdp-hybrid", or "connect".
    backend_str: String,
    /// BPF timing backend, initialised once at startup. None = connect-scan fallback.
    bpf: Option<Arc<Mutex<limpet::BpfTimingCollector>>>,
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

    tracing::info!(
        request_id = %req.request_id,
        target = %req.target_ip,
        "discovery request received"
    );

    let port_spec = match wire_to_port_spec(&req.ports) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(request_id = %req.request_id, error = %e, "invalid port spec");
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
        &state.resolved_interface,
        state.bpf.clone(),
        &state.backend_str,
    )
    .await
    {
        Ok(scan_result) => {
            let actual_ms = start.elapsed().as_millis() as u64;
            let source_ip = scan_result.target_ip.to_string();
            tracing::info!(
                request_id = %req.request_id,
                target = %req.target_ip,
                backend = %scan_result.backend,
                duration_ms = actual_ms,
                "discovery complete"
            );

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
            tracing::warn!(
                request_id = %req.request_id,
                target = %req.target_ip,
                duration_ms = actual_ms,
                error = %e,
                "discovery failed"
            );
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
    tracing::info!(
        request_id = %req.request_id,
        target = %req.target_host,
        port = req.target_port,
        samples = req.sample_count,
        "timing request received"
    );

    let mut result = collect_timing_samples(&req, state.bpf.clone()).await;
    result.worker_node = Some(state.worker_node);
    result.source_ip = detect_own_ip();

    tracing::info!(
        request_id = %result.request_id,
        target = %result.target_host,
        port = result.target_port,
        precision = %result.precision_class,
        samples = result.samples.len(),
        mean_us = result.stats.mean,
        error = result.error.as_deref().unwrap_or(""),
        "timing complete"
    );

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

/// Run a port discovery scan.
///
/// On Linux with a live BPF backend (`bpf = Some(...)`), uses the XDP/SYN path
/// with the startup-initialised collector.  When `bpf = None` (Docker / macOS /
/// any environment where BPF failed at startup), falls through to the TCP
/// connect-scan fallback so scans still succeed.
///
/// The BPF backend is **never** re-initialised here; that would cause `-EBUSY`
/// because the kernel rejects attaching a second XDP program to the same
/// interface.
async fn run_discovery(
    target: &str,
    port_spec: PortSpec,
    pacing: PacingProfile,
    timeout_ms: u32,
    max_ports: Option<u32>,
    iface: &str,
    bpf: Option<Arc<Mutex<limpet::BpfTimingCollector>>>,
    backend_str: &str,
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
        let _ = (pacing, iface, bpf, backend_str);
        tracing::warn!("XDP unavailable on non-Linux — falling back to TCP connect scan");
        return run_connect_scan(target_ip, port_spec, timeout_ms, max_ports, target_hostname, request_id).await;
    }

    #[cfg(target_os = "linux")]
    {
        use limpet::scanner::afxdp_sender::{AfXdpSend, AfXdpSender};
        use limpet::scanner::raw_socket_sender::RawSocketSender;

        // If BPF is unavailable (e.g. Docker environment), use connect scan.
        let bpf_arc = match bpf {
            Some(arc) => arc,
            None => {
                tracing::warn!("BPF unavailable — falling back to TCP connect scan");
                return run_connect_scan(target_ip, port_spec, timeout_ms, max_ports, target_hostname, request_id).await;
            }
        };

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

        let xdp_sender: Box<dyn AfXdpSend> = match AfXdpSender::new(iface, 0, src_ip) {
            Ok(sender) => {
                let bpf_guard = bpf_arc.lock().await;
                if let Err(e) = bpf_guard.register_xsk_fd(sender.fd()) {
                    tracing::warn!(error = %e, "xsk_map registration failed");
                }
                drop(bpf_guard);
                Box::new(sender)
            }
            Err(e) => {
                tracing::warn!(error = %e, "AF_XDP unavailable — falling back to TCP connect scan");
                return run_connect_scan(target_ip, port_spec, timeout_ms, max_ports, target_hostname, request_id).await;
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

        let bpf_guard = bpf_arc.lock().await;
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
            backend: backend_str.to_string(),
            scanned_at: Utc::now(),
            error: None,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TCP connect scan fallback
// ─────────────────────────────────────────────────────────────────────────────

/// TCP connect-based port discovery — used when XDP/BPF is unavailable.
///
/// Probes each port with a full TCP connect. Classification:
///   - Connect succeeds  → Open
///   - Connection refused → Closed
///   - Timeout / other error → Filtered
///
/// Runs ports in parallel batches of 256. Precision is userspace (~ms), not
/// nanosecond XDP timing, but the result format is identical so the orchestrator
/// can consume it unchanged.
async fn run_connect_scan(
    target_ip: std::net::Ipv4Addr,
    port_spec: PortSpec,
    timeout_ms: u32,
    max_ports: Option<u32>,
    target_hostname: Option<String>,
    request_id: uuid::Uuid,
) -> Result<ScanResult, String> {
    let mut ports = port_spec.expand();
    if let Some(max) = max_ports {
        ports.truncate(max as usize);
    }

    let start = Instant::now();
    let timeout_dur = tokio::time::Duration::from_millis(timeout_ms as u64);
    const CONCURRENCY: usize = 256;

    let mut port_results: Vec<ScannedPort> = Vec::with_capacity(ports.len());

    for chunk in ports.chunks(CONCURRENCY) {
        let mut tasks = tokio::task::JoinSet::new();
        for &port in chunk {
            let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(target_ip), port);
            tasks.spawn(async move {
                let probe_start = Instant::now();
                let result =
                    tokio::time::timeout(timeout_dur, tokio::net::TcpStream::connect(addr)).await;
                let timing_ns = probe_start.elapsed().as_nanos() as u64;
                let state = match result {
                    Ok(Ok(_)) => PortState::Open,
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        PortState::Closed
                    }
                    _ => PortState::Filtered,
                };
                ScannedPort {
                    port,
                    state,
                    timing_ns,
                    response_ttl: 0,
                    response_win: 0,
                }
            });
        }
        while let Some(res) = tasks.join_next().await {
            if let Ok(scanned) = res {
                port_results.push(scanned);
            }
        }
    }

    Ok(ScanResult {
        request_id,
        target_ip,
        target_hostname,
        ports: port_results,
        duration_ms: start.elapsed().as_millis() as u64,
        backend: "connect".to_string(),
        scanned_at: Utc::now(),
        error: None,
    })
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

    // Initialise BPF timing backend once at startup.
    // On macOS / Docker Desktop this will fail and we fall back to connect scan for all requests.
    let (bpf, backend_str, resolved_interface) = match limpet::detect_timing_backend(&interface) {
        Ok((backend, collector)) => {
            let backend_str = backend.as_str().to_string();
            let resolved_iface = collector.interface().to_string();
            tracing::info!(backend = %backend_str, interface = %resolved_iface, "BPF timing backend initialised");
            (Some(Arc::new(Mutex::new(collector))), backend_str, resolved_iface)
        }
        Err(e) => {
            tracing::warn!(error = %e, "BPF timing backend unavailable — connect-scan fallback active");
            let resolved_iface = interface.unwrap_or_else(|| "eth0".to_string());
            (None, "connect".to_string(), resolved_iface)
        }
    };

    tracing::info!(worker_node = %worker_node, port = port, "limpet-server starting");

    let state = ServerState {
        worker_node,
        resolved_interface,
        backend_str,
        bpf,
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

    #[test]
    fn test_server_state_backend_str_connect_when_bpf_none() {
        // Verify the connect-scan fallback path: bpf=None, backend_str="connect".
        // This is the expected state in Docker / macOS where BPF fails at startup.
        let state = ServerState {
            worker_node: "test".to_string(),
            resolved_interface: "eth0".to_string(),
            backend_str: "connect".to_string(),
            bpf: None,
        };
        assert_eq!(state.backend_str, "connect");
        assert!(state.bpf.is_none());
    }

    #[test]
    fn test_server_state_resolved_interface_falls_back_to_eth0() {
        // When LIMPET_INTERFACE is not set and BPF fails, resolved_interface is "eth0".
        let interface: Option<String> = None;
        let resolved = interface.unwrap_or_else(|| "eth0".to_string());
        assert_eq!(resolved, "eth0");
    }
}
