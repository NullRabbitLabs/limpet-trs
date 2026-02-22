//! limpet-consumer — Redis Streams consumer replacing limpet-server HTTP.
//!
//! Reads port discovery and timing requests from Redis Streams, runs the
//! limpet scan engine, and publishes results back. Uses XREADGROUP consumer
//! groups and the delayed-ACK pattern (publish result first, then ACK).
//!
//! ## Streams
//!
//! | Variable                             | Default                      |
//! |--------------------------------------|------------------------------|
//! | `LIMPET_DISCOVERY_REQUEST_STREAM`    | limpet.discovery.request     |
//! | `LIMPET_DISCOVERY_RESULT_STREAM`     | limpet.discovery.result      |
//! | `LIMPET_TIMING_REQUEST_STREAM`       | limpet.timing.request        |
//! | `LIMPET_TIMING_RESULT_STREAM`        | limpet.timing.result         |
//! | `LIMPET_CONSUMER_GROUP`              | limpet-discovery-sub         |
//! | `LIMPET_TIMING_GROUP`                | limpet-timing-sub            |
//! | `REDIS_URL`                          | redis://127.0.0.1:6379       |
//! | `LIMPET_INTERFACE`                   | auto-detected                |
//! | `WORKER_NODE`                        | hostname                     |

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use limpet::scanner::collector::DiscoveryCollector;
use limpet::scanner::stealth::{PacingProfile, StealthProfile};
use limpet::scanner::syn_sender::{detect_source_ip, SynScanner};
use limpet::timing::collect_timing_samples;
use limpet::{PortSpec, PortState, ScanResult, ScannedPort, TimingRequest};

// ─────────────────────────────────────────────────────────────────────────────
// BPF state (shared with server.rs pattern)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct BpfState {
    interface: String,
    backend_str: String,
    collector: Option<Arc<Mutex<limpet::BpfTimingCollector>>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Consumer configuration
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ConsumerConfig {
    redis_url: String,
    discovery_request_stream: String,
    discovery_result_stream: String,
    timing_request_stream: String,
    timing_result_stream: String,
    discovery_group: String,
    timing_group: String,
    consumer_name: String,
    worker_node: String,
}

impl ConsumerConfig {
    fn from_env() -> Self {
        let consumer_name = std::env::var("LIMPET_CONSUMER_NAME").unwrap_or_else(|_| {
            nix::unistd::gethostname()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| format!("limpet-consumer-{}", std::process::id()))
        });
        let worker_node = std::env::var("WORKER_NODE").unwrap_or_else(|_| consumer_name.clone());

        Self {
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            discovery_request_stream: std::env::var("LIMPET_DISCOVERY_REQUEST_STREAM")
                .unwrap_or_else(|_| "limpet.discovery.request".to_string()),
            discovery_result_stream: std::env::var("LIMPET_DISCOVERY_RESULT_STREAM")
                .unwrap_or_else(|_| "limpet.discovery.result".to_string()),
            timing_request_stream: std::env::var("LIMPET_TIMING_REQUEST_STREAM")
                .unwrap_or_else(|_| "limpet.timing.request".to_string()),
            timing_result_stream: std::env::var("LIMPET_TIMING_RESULT_STREAM")
                .unwrap_or_else(|_| "limpet.timing.result".to_string()),
            discovery_group: std::env::var("LIMPET_CONSUMER_GROUP")
                .unwrap_or_else(|_| "limpet-discovery-sub".to_string()),
            timing_group: std::env::var("LIMPET_TIMING_GROUP")
                .unwrap_or_else(|_| "limpet-timing-sub".to_string()),
            consumer_name,
            worker_node,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire types — JSON field names match Go domain.DiscoveryRequest/Result
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DiscoveryRequest {
    request_id: String,
    scan_id: Option<String>,
    target_ip: String,
    target_hostname: Option<String>,
    ports: PortSpecWire,
    timeout_ms: u64,
    #[serde(default)]
    #[allow(dead_code)]
    sample_count: u32,
    pacing_profile: Option<String>,
    #[serde(default)]
    max_ports: Option<u32>,
    // Shard metadata — Go uses anonymous struct embedding so these fields are
    // serialised flat (not nested under "shard_meta").
    #[serde(default)]
    base_request_id: String,
    #[serde(default)]
    shard_index: i32,
    #[serde(default)]
    total_shards: i32,
}

#[derive(Debug, Deserialize)]
struct PortSpecWire {
    #[serde(rename = "type")]
    kind: String,
    value: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct DiscoveredPortWire {
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
    port_results: Vec<DiscoveredPortWire>,
    actual_duration_ms: u64,
    scanner_backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worker_node: Option<String>,
    // Shard metadata echoed back flat — Go's DiscoveryResultMessage embeds
    // ShardMeta anonymously, so these fields appear at the top level in JSON.
    #[serde(skip_serializing_if = "String::is_empty")]
    base_request_id: String,
    shard_index: i32,
    total_shards: i32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Port spec + pacing helpers (mirror server.rs)
// ─────────────────────────────────────────────────────────────────────────────

fn wire_to_port_spec(spec: &PortSpecWire) -> Result<PortSpec, String> {
    match spec.kind.as_str() {
        "Explicit" => {
            let ports = match &spec.value {
                Some(serde_json::Value::Array(arr)) => arr
                    .iter()
                    .map(|v| {
                        v.as_u64()
                            .and_then(|n| u16::try_from(n).ok())
                            .ok_or_else(|| format!("invalid port in Explicit spec: {v}"))
                    })
                    .collect::<Result<Vec<u16>, _>>()?,
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
// Scan engine — mirrors server.rs run_discovery / run_connect_scan
// ─────────────────────────────────────────────────────────────────────────────

async fn run_discovery(
    target: &str,
    port_spec: PortSpec,
    pacing: PacingProfile,
    timeout_ms: u32,
    max_ports: Option<u32>,
    bpf_state: &BpfState,
) -> Result<ScanResult, String> {
    let start = Instant::now();

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
        let _ = (pacing, bpf_state, start);
        tracing::warn!("XDP unavailable on non-Linux — falling back to TCP connect scan");
        return run_connect_scan(
            target_ip,
            port_spec,
            timeout_ms,
            max_ports,
            target_hostname,
            request_id,
        )
        .await;
    }

    #[cfg(target_os = "linux")]
    {
        use limpet::scanner::afxdp_sender::{AfXdpSend, AfXdpSender};

        let bpf_arc = match bpf_state.collector.clone() {
            Some(arc) => arc,
            None => {
                tracing::warn!("BPF unavailable — falling back to TCP connect scan");
                return run_connect_scan(
                    target_ip,
                    port_spec,
                    timeout_ms,
                    max_ports,
                    target_hostname,
                    request_id,
                )
                .await;
            }
        };

        let src_ip =
            detect_source_ip(target_ip).map_err(|e| format!("source IP detection failed: {e}"))?;

        let mut stealth = StealthProfile::linux_6x_default();
        pacing.apply_to(&mut stealth);

        let mut ports = port_spec.expand();
        if let Some(max) = max_ports {
            ports.truncate(max as usize);
        }
        let batch_size = pacing.batch_size();
        let timeout = Duration::from_millis(timeout_ms as u64);

        let xdp_sender: Box<dyn AfXdpSend> = match AfXdpSender::new(&bpf_state.interface, 0, src_ip)
        {
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
                return run_connect_scan(
                    target_ip,
                    port_spec,
                    timeout_ms,
                    max_ports,
                    target_hostname,
                    request_id,
                )
                .await;
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

        Ok(ScanResult {
            request_id,
            target_ip,
            target_hostname,
            ports: scanned_ports,
            duration_ms: start.elapsed().as_millis() as u64,
            backend: bpf_state.backend_str.clone(),
            scanned_at: Utc::now(),
            error: None,
        })
    }
}

async fn run_connect_scan(
    target_ip: Ipv4Addr,
    port_spec: PortSpec,
    timeout_ms: u32,
    max_ports: Option<u32>,
    target_hostname: Option<String>,
    request_id: Uuid,
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

fn detect_own_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Redis helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Ensure consumer group exists on the stream. Ignores BUSYGROUP error.
async fn ensure_group(
    conn: &mut redis::aio::MultiplexedConnection,
    stream: &str,
    group: &str,
) -> Result<(), String> {
    let result: redis::RedisResult<()> = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(stream)
        .arg(group)
        .arg("$")
        .arg("MKSTREAM")
        .query_async(conn)
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) if e.to_string().contains("BUSYGROUP") => Ok(()),
        Err(e) => Err(format!("XGROUP CREATE failed for {stream}/{group}: {e}")),
    }
}

/// Parse a single message payload from an XREADGROUP response entry.
/// The orchestrator writes the JSON body under the "data" field.
fn extract_payload(entry: &[(String, redis::Value)]) -> Option<String> {
    for (field, val) in entry {
        if field == "data" {
            if let redis::Value::BulkString(bytes) = val {
                return String::from_utf8(bytes.clone()).ok();
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovery consumer loop
// ─────────────────────────────────────────────────────────────────────────────

async fn discovery_consumer_loop(cfg: ConsumerConfig, bpf: Arc<BpfState>) {
    let client = redis::Client::open(cfg.redis_url.clone())
        .expect("failed to create Redis client for discovery consumer");

    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("failed to connect to Redis for discovery consumer");

    if let Err(e) = ensure_group(
        &mut conn,
        &cfg.discovery_request_stream,
        &cfg.discovery_group,
    )
    .await
    {
        tracing::error!("{e}");
        return;
    }

    tracing::info!(
        stream = %cfg.discovery_request_stream,
        group = %cfg.discovery_group,
        consumer = %cfg.consumer_name,
        "discovery consumer started"
    );

    loop {
        let read_result: redis::RedisResult<redis::Value> = redis::cmd("XREADGROUP")
            .arg("GROUP")
            .arg(&cfg.discovery_group)
            .arg(&cfg.consumer_name)
            .arg("COUNT")
            .arg(1)
            .arg("BLOCK")
            .arg(5000)
            .arg("STREAMS")
            .arg(&cfg.discovery_request_stream)
            .arg(">")
            .query_async(&mut conn)
            .await;

        let val = match read_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "XREADGROUP error (discovery), retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        // val is Option<Vec<(stream_name, Vec<(id, fields)>)>>
        let streams = match parse_xreadgroup_response(val) {
            Some(s) => s,
            None => continue, // timeout / empty
        };

        for (msg_id, payload_str) in streams {
            let req: DiscoveryRequest = match serde_json::from_str(&payload_str) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(msg_id = %msg_id, error = %e, "failed to deserialize discovery request, acking to clear");
                    let _: redis::RedisResult<()> = redis::cmd("XACK")
                        .arg(&cfg.discovery_request_stream)
                        .arg(&cfg.discovery_group)
                        .arg(&msg_id)
                        .query_async(&mut conn)
                        .await;
                    continue;
                }
            };

            tracing::info!(
                request_id = %req.request_id,
                scan_id = req.scan_id.as_deref().unwrap_or(""),
                target = %req.target_ip,
                shard_index = req.shard_index,
                total_shards = req.total_shards,
                "discovery request received"
            );

            let start = Instant::now();
            let result = process_discovery_request(&req, &bpf, &cfg.worker_node).await;
            let actual_ms = start.elapsed().as_millis() as u64;

            tracing::info!(
                request_id = %req.request_id,
                duration_ms = actual_ms,
                ports_scanned = result.ports_scanned,
                backend = %result.scanner_backend,
                "discovery complete"
            );

            // Publish result BEFORE acking (delayed-ack pattern)
            match serde_json::to_string(&result) {
                Ok(json) => {
                    let xadd_result: redis::RedisResult<String> = redis::cmd("XADD")
                        .arg(&cfg.discovery_result_stream)
                        .arg("*")
                        .arg("payload")
                        .arg(&json)
                        .query_async(&mut conn)
                        .await;
                    if let Err(e) = xadd_result {
                        tracing::error!(error = %e, "XADD discovery result failed");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to serialize discovery result");
                }
            }

            // ACK after publishing result
            let _: redis::RedisResult<()> = redis::cmd("XACK")
                .arg(&cfg.discovery_request_stream)
                .arg(&cfg.discovery_group)
                .arg(&msg_id)
                .query_async(&mut conn)
                .await;
        }
    }
}

async fn process_discovery_request(
    req: &DiscoveryRequest,
    bpf: &BpfState,
    worker_node: &str,
) -> DiscoveryResult {
    let port_spec = match wire_to_port_spec(&req.ports) {
        Ok(s) => s,
        Err(e) => {
            return DiscoveryResult {
                request_id: req.request_id.clone(),
                scan_id: req.scan_id.clone(),
                target_ip: req.target_ip.clone(),
                target_hostname: req.target_hostname.clone(),
                ports_scanned: 0,
                port_results: vec![],
                actual_duration_ms: 0,
                scanner_backend: "error".to_string(),
                error: Some(format!("invalid port spec: {e}")),
                source_ip: None,
                worker_node: Some(worker_node.to_string()),
                base_request_id: req.base_request_id.clone(),
                shard_index: req.shard_index,
                total_shards: req.total_shards,
            };
        }
    };

    let pacing = req
        .pacing_profile
        .as_deref()
        .map(pacing_from_str)
        .unwrap_or(PacingProfile::Normal);

    let start = Instant::now();
    let source_ip = detect_own_ip();

    match run_discovery(
        &req.target_ip,
        port_spec,
        pacing,
        req.timeout_ms as u32,
        req.max_ports,
        bpf,
    )
    .await
    {
        Ok(scan_result) => {
            let actual_ms = start.elapsed().as_millis() as u64;
            let port_results: Vec<DiscoveredPortWire> = scan_result
                .ports
                .into_iter()
                .map(|p| DiscoveredPortWire {
                    port: p.port,
                    state: p.state,
                    timing_ns: p.timing_ns,
                    response_ttl: p.response_ttl,
                    response_win: p.response_win,
                })
                .collect();
            let ports_scanned = port_results.len() as u32;

            DiscoveryResult {
                request_id: req.request_id.clone(),
                scan_id: req.scan_id.clone(),
                target_ip: req.target_ip.clone(),
                target_hostname: req.target_hostname.clone().or(scan_result.target_hostname),
                ports_scanned,
                port_results,
                actual_duration_ms: actual_ms,
                scanner_backend: scan_result.backend,
                error: scan_result.error,
                source_ip,
                worker_node: Some(worker_node.to_string()),
                base_request_id: req.base_request_id.clone(),
                shard_index: req.shard_index,
                total_shards: req.total_shards,
            }
        }
        Err(e) => {
            let actual_ms = start.elapsed().as_millis() as u64;
            DiscoveryResult {
                request_id: req.request_id.clone(),
                scan_id: req.scan_id.clone(),
                target_ip: req.target_ip.clone(),
                target_hostname: req.target_hostname.clone(),
                ports_scanned: 0,
                port_results: vec![],
                actual_duration_ms: actual_ms,
                scanner_backend: "unavailable".to_string(),
                error: Some(e),
                source_ip,
                worker_node: Some(worker_node.to_string()),
                base_request_id: req.base_request_id.clone(),
                shard_index: req.shard_index,
                total_shards: req.total_shards,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Timing consumer loop
// ─────────────────────────────────────────────────────────────────────────────

async fn timing_consumer_loop(cfg: ConsumerConfig, bpf: Arc<BpfState>) {
    let client = redis::Client::open(cfg.redis_url.clone())
        .expect("failed to create Redis client for timing consumer");

    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("failed to connect to Redis for timing consumer");

    if let Err(e) = ensure_group(&mut conn, &cfg.timing_request_stream, &cfg.timing_group).await {
        tracing::error!("{e}");
        return;
    }

    tracing::info!(
        stream = %cfg.timing_request_stream,
        group = %cfg.timing_group,
        consumer = %cfg.consumer_name,
        "timing consumer started"
    );

    loop {
        let read_result: redis::RedisResult<redis::Value> = redis::cmd("XREADGROUP")
            .arg("GROUP")
            .arg(&cfg.timing_group)
            .arg(&cfg.consumer_name)
            .arg("COUNT")
            .arg(1)
            .arg("BLOCK")
            .arg(5000)
            .arg("STREAMS")
            .arg(&cfg.timing_request_stream)
            .arg(">")
            .query_async(&mut conn)
            .await;

        let val = match read_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "XREADGROUP error (timing), retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        let streams = match parse_xreadgroup_response(val) {
            Some(s) => s,
            None => continue,
        };

        for (msg_id, payload_str) in streams {
            let req: TimingRequest = match serde_json::from_str(&payload_str) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(msg_id = %msg_id, error = %e, "failed to deserialize timing request, acking to clear");
                    let _: redis::RedisResult<()> = redis::cmd("XACK")
                        .arg(&cfg.timing_request_stream)
                        .arg(&cfg.timing_group)
                        .arg(&msg_id)
                        .query_async(&mut conn)
                        .await;
                    continue;
                }
            };

            tracing::info!(
                request_id = %req.request_id,
                target = %req.target_host,
                port = req.target_port,
                samples = req.sample_count,
                "timing request received"
            );

            let mut result = collect_timing_samples(&req, bpf.collector.clone()).await;
            result.worker_node = Some(cfg.worker_node.clone());
            result.source_ip = detect_own_ip();

            tracing::info!(
                request_id = %result.request_id,
                target = %result.target_host,
                port = result.target_port,
                precision = %result.precision_class,
                samples = result.samples.len(),
                error = result.error.as_deref().unwrap_or(""),
                "timing complete"
            );

            // Publish result BEFORE acking (delayed-ack pattern)
            match serde_json::to_string(&result) {
                Ok(json) => {
                    let xadd_result: redis::RedisResult<String> = redis::cmd("XADD")
                        .arg(&cfg.timing_result_stream)
                        .arg("*")
                        .arg("payload")
                        .arg(&json)
                        .query_async(&mut conn)
                        .await;
                    if let Err(e) = xadd_result {
                        tracing::error!(error = %e, "XADD timing result failed");
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to serialize timing result");
                }
            }

            // ACK after publishing result
            let _: redis::RedisResult<()> = redis::cmd("XACK")
                .arg(&cfg.timing_request_stream)
                .arg(&cfg.timing_group)
                .arg(&msg_id)
                .query_async(&mut conn)
                .await;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XREADGROUP response parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parse an XREADGROUP response into (message_id, payload_json) pairs.
/// Returns None on empty / timeout responses.
fn parse_xreadgroup_response(val: redis::Value) -> Option<Vec<(String, String)>> {
    // Response structure: Array[Array[stream_name, Array[Array[id, Array[field, value, ...]]]]]
    // When BLOCK timeout fires with no messages, the server returns nil (Nil value).
    let outer = match val {
        redis::Value::Array(arr) if !arr.is_empty() => arr,
        redis::Value::Nil => return None,
        _ => return None,
    };

    let mut results = Vec::new();

    for stream_entry in outer {
        let stream_parts = match stream_entry {
            redis::Value::Array(parts) if parts.len() >= 2 => parts,
            _ => continue,
        };

        let messages = match &stream_parts[1] {
            redis::Value::Array(msgs) => msgs,
            _ => continue,
        };

        for msg in messages {
            let msg_parts = match msg {
                redis::Value::Array(parts) if parts.len() >= 2 => parts,
                _ => continue,
            };

            let msg_id = match &msg_parts[0] {
                redis::Value::BulkString(bytes) => String::from_utf8_lossy(bytes).to_string(),
                redis::Value::SimpleString(s) => s.clone(),
                _ => continue,
            };

            let fields: Vec<(String, redis::Value)> = match &msg_parts[1] {
                redis::Value::Array(arr) if arr.len() % 2 == 0 => arr
                    .chunks(2)
                    .filter_map(|chunk| {
                        let key = match &chunk[0] {
                            redis::Value::BulkString(b) => String::from_utf8_lossy(b).to_string(),
                            redis::Value::SimpleString(s) => s.clone(),
                            _ => return None,
                        };
                        Some((key, chunk[1].clone()))
                    })
                    .collect(),
                _ => continue,
            };

            if let Some(payload) = extract_payload(&fields) {
                results.push((msg_id, payload));
            }
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cfg = ConsumerConfig::from_env();
    let interface = std::env::var("LIMPET_INTERFACE").ok();

    tracing::info!(
        worker_node = %cfg.worker_node,
        consumer = %cfg.consumer_name,
        redis_url = %cfg.redis_url,
        "limpet-consumer starting"
    );

    // Initialise BPF once at startup (same as server.rs)
    let bpf = match limpet::detect_timing_backend(&interface) {
        Ok((backend, collector)) => {
            let backend_str = backend.as_str().to_string();
            let iface = collector.interface().to_string();
            tracing::info!(backend = %backend_str, interface = %iface, "BPF timing backend initialised");
            BpfState {
                interface: iface,
                backend_str,
                collector: Some(Arc::new(Mutex::new(collector))),
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "BPF timing backend unavailable — connect-scan fallback active");
            BpfState {
                interface: interface.unwrap_or_else(|| "eth0".to_string()),
                backend_str: "connect".to_string(),
                collector: None,
            }
        }
    };

    let bpf = Arc::new(bpf);

    let discovery_cfg = cfg.clone();
    let discovery_bpf = Arc::clone(&bpf);
    let discovery_handle = tokio::spawn(async move {
        discovery_consumer_loop(discovery_cfg, discovery_bpf).await;
    });

    let timing_cfg = cfg.clone();
    let timing_bpf = Arc::clone(&bpf);
    let timing_handle = tokio::spawn(async move {
        timing_consumer_loop(timing_cfg, timing_bpf).await;
    });

    // Run until one task exits (which would indicate an unrecoverable error)
    tokio::select! {
        _ = discovery_handle => tracing::error!("discovery consumer loop exited unexpectedly"),
        _ = timing_handle => tracing::error!("timing consumer loop exited unexpectedly"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_discovery_request() {
        // Go's DiscoveryRequestMessage embeds ShardMeta anonymously — fields are flat.
        let json = r#"{
            "request_id": "550e8400-e29b-41d4-a716-446655440000",
            "scan_id": "660e8400-e29b-41d4-a716-446655440000",
            "target_ip": "10.0.0.1",
            "ports": {"type": "Explicit", "value": [22, 80, 443]},
            "timeout_ms": 5000,
            "sample_count": 10,
            "base_request_id": "770e8400-e29b-41d4-a716-446655440000",
            "shard_index": 0,
            "total_shards": 2
        }"#;
        let req: DiscoveryRequest = serde_json::from_str(json).expect("deserialize failed");
        assert_eq!(req.request_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(req.target_ip, "10.0.0.1");
        assert_eq!(req.timeout_ms, 5000);
        assert_eq!(req.shard_index, 0);
        assert_eq!(req.total_shards, 2);
    }

    #[test]
    fn test_deserialize_discovery_request_non_sharded() {
        // Non-sharded messages omit base_request_id and total_shards (Go omitempty).
        let json = r#"{
            "request_id": "550e8400-e29b-41d4-a716-446655440002",
            "target_ip": "10.0.0.2",
            "ports": {"type": "Explicit", "value": [80]},
            "timeout_ms": 3000,
            "shard_index": 0
        }"#;
        let req: DiscoveryRequest = serde_json::from_str(json).expect("deserialize failed");
        assert_eq!(req.base_request_id, "");
        assert_eq!(req.shard_index, 0);
        assert_eq!(req.total_shards, 0);
    }

    #[test]
    fn test_deserialize_timing_request() {
        let json = r#"{
            "request_id": "550e8400-e29b-41d4-a716-446655440001",
            "scan_id": "660e8400-e29b-41d4-a716-446655440001",
            "target_host": "192.168.1.1",
            "target_port": 443,
            "sample_count": 10,
            "timeout_ms": 3000
        }"#;
        let req: TimingRequest = serde_json::from_str(json).expect("deserialize failed");
        assert_eq!(req.target_host, "192.168.1.1");
        assert_eq!(req.target_port, 443);
        assert_eq!(req.sample_count, 10);
    }

    #[test]
    fn test_build_discovery_result_error_path() {
        let req = DiscoveryRequest {
            request_id: "test-req-id".to_string(),
            scan_id: Some("test-scan-id".to_string()),
            target_ip: "10.0.0.1".to_string(),
            target_hostname: None,
            ports: PortSpecWire {
                kind: "Unknown".to_string(), // will cause an error
                value: None,
            },
            timeout_ms: 5000,
            sample_count: 10,
            pacing_profile: None,
            max_ports: None,
            base_request_id: "base-123".to_string(),
            shard_index: 1,
            total_shards: 3,
        };

        let bpf = BpfState {
            interface: "eth0".to_string(),
            backend_str: "connect".to_string(),
            collector: None,
        };

        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let result = process_discovery_request(&req, &bpf, "test-node").await;
            assert!(result.error.is_some());
            assert_eq!(result.scanner_backend, "error");
            assert_eq!(result.base_request_id, "base-123");
            assert_eq!(result.shard_index, 1);
            assert_eq!(result.total_shards, 3);
            assert_eq!(result.worker_node.as_deref(), Some("test-node"));
        });
    }

    #[test]
    fn test_discovery_result_serializes_flat_shard_fields() {
        // Verify the result JSON has flat shard fields (not nested under "shard_meta")
        // matching Go's anonymous struct embedding behaviour.
        let result = DiscoveryResult {
            request_id: "req-1".to_string(),
            scan_id: None,
            target_ip: "10.0.0.1".to_string(),
            target_hostname: None,
            ports_scanned: 0,
            port_results: vec![],
            actual_duration_ms: 10,
            scanner_backend: "connect".to_string(),
            error: None,
            source_ip: None,
            worker_node: None,
            base_request_id: "base-abc".to_string(),
            shard_index: 1,
            total_shards: 2,
        };
        let json = serde_json::to_string(&result).expect("serialize failed");
        let v: serde_json::Value = serde_json::from_str(&json).expect("re-parse failed");
        // Fields must be at top level, not nested under "shard_meta"
        assert_eq!(v["base_request_id"], "base-abc");
        assert_eq!(v["shard_index"], 1);
        assert_eq!(v["total_shards"], 2);
        assert!(
            v.get("shard_meta").is_none(),
            "shard_meta must not be a nested key"
        );
    }

    #[test]
    fn test_wire_to_port_spec_explicit() {
        let spec = PortSpecWire {
            kind: "Explicit".to_string(),
            value: Some(serde_json::json!([22, 80, 443])),
        };
        let result = wire_to_port_spec(&spec);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wire_to_port_spec_invalid_type() {
        let spec = PortSpecWire {
            kind: "Common".to_string(),
            value: None,
        };
        let result = wire_to_port_spec(&spec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("orchestrator must expand"));
    }
}
