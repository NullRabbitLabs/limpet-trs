//! Scanning engine — owns BPF state and provides `discover` + `collect_timing` API.
//!
//! Consolidates scanning logic previously duplicated across CLI, consumer, and
//! BPF modules. The consumer binary becomes pure Redis glue; all scanning
//! orchestration lives here.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::scanner::collector::DiscoveryCollector;
use crate::scanner::stealth::{PacingProfile, StealthProfile};
use crate::scanner::syn_sender::SynScanner;
use crate::timing::xdp::BpfTimingCollector;
use crate::{PortState, ScanResult, ScannedPort, TimingBackend, TimingRequest, TimingResult};

/// Configuration for creating an [`Engine`].
pub struct ScanEngineConfig {
    /// Network interface for XDP (None = auto-detect from /proc/net/route).
    pub interface: Option<String>,
    /// When true, use raw socket TX only (no AF_XDP redirect).
    /// BPF timestamps packets but XDP_PASS lets them through to the kernel.
    pub passthrough: bool,
}

/// Scanning engine. Shared via `Arc<Engine>` between discovery and timing loops.
pub enum Engine {
    /// BPF-backed: XDP timestamps + SYN scanning.
    Bpf(ScanEngine),
    /// Fallback: BPF unavailable, TCP connect scan only.
    ConnectOnly {
        /// Network interface name (informational).
        interface: String,
    },
}

/// Inner BPF-backed scan engine.
pub struct ScanEngine {
    collector: Arc<Mutex<BpfTimingCollector>>,
    scanner: Arc<Mutex<SynScanner>>,
    interface: String,
    backend: TimingBackend,
    #[allow(dead_code)]
    passthrough: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve a hostname or IP string to an `Ipv4Addr`.
///
/// Returns `(ip, hostname)` where `hostname` is `Some` if DNS was performed.
pub fn resolve_target(target: &str) -> Result<(Ipv4Addr, Option<String>), String> {
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Ok((ip, None));
    }
    use std::net::ToSocketAddrs;
    let addrs = format!("{target}:0")
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for '{target}': {e}"))?;
    for addr in addrs {
        if let std::net::IpAddr::V4(ip) = addr.ip() {
            return Ok((ip, Some(target.to_string())));
        }
    }
    Err(format!("no IPv4 address found for '{target}'"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────────────────────

impl Engine {
    /// Create a new scanning engine.
    ///
    /// Attempts to initialize BPF timing backend. Falls back to `ConnectOnly`
    /// when BPF is unavailable (non-Linux, missing CAP_BPF, etc.).
    pub fn new(config: ScanEngineConfig) -> Self {
        if config.passthrough {
            tracing::info!("passthrough mode: using raw socket TX, no AF_XDP redirect");
        }

        #[cfg(not(target_os = "linux"))]
        {
            let iface = config.interface.unwrap_or_else(|| "lo0".to_string());
            tracing::warn!("BPF unavailable on non-Linux — connect-scan fallback active");
            return Engine::ConnectOnly { interface: iface };
        }

        #[cfg(target_os = "linux")]
        {
            match crate::timing::detect_timing_backend(&config.interface) {
                Ok((backend, collector)) => {
                    let iface = collector.interface().to_string();
                    tracing::info!(
                        backend = %backend,
                        interface = %iface,
                        passthrough = config.passthrough,
                        "BPF timing backend initialised"
                    );
                    let bpf = Arc::new(Mutex::new(collector));
                    match Self::create_scanner(&iface, &bpf, config.passthrough) {
                        Some(scanner) => Engine::Bpf(ScanEngine {
                            collector: bpf,
                            scanner,
                            interface: iface,
                            backend,
                            passthrough: config.passthrough,
                        }),
                        None => {
                            tracing::warn!(
                                "scanner creation failed — connect-scan fallback active"
                            );
                            Engine::ConnectOnly { interface: iface }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "BPF timing backend unavailable — connect-scan fallback active"
                    );
                    let iface = config.interface.unwrap_or_else(|| "eth0".to_string());
                    Engine::ConnectOnly { interface: iface }
                }
            }
        }
    }

    /// Create a `SynScanner` with the appropriate sender.
    ///
    /// In passthrough mode, uses `RawSocketSender` only (no AF_XDP redirect).
    /// Otherwise creates a `HybridSender` and registers its AF_XDP fd in xsk_map.
    #[cfg(target_os = "linux")]
    fn create_scanner(
        iface: &str,
        bpf: &Arc<Mutex<BpfTimingCollector>>,
        passthrough: bool,
    ) -> Option<Arc<Mutex<SynScanner>>> {
        use crate::scanner::afxdp_sender::AfXdpSend;
        use crate::scanner::hybrid_sender::HybridSender;
        use crate::scanner::raw_socket_sender::RawSocketSender;
        use crate::scanner::syn_sender::interface_source_ip;

        let src_ip = match interface_source_ip(iface) {
            Ok(ip) => ip,
            Err(_) => {
                tracing::warn!(interface = %iface, "no IPv4 on interface, scanner unavailable");
                return None;
            }
        };

        let xdp_sender: Box<dyn AfXdpSend> = if passthrough {
            match RawSocketSender::new(src_ip, Some(iface)) {
                Ok(s) => Box::new(s),
                Err(e) => {
                    tracing::error!(error = %e, "raw socket sender failed");
                    return None;
                }
            }
        } else {
            match HybridSender::new(iface, 0, src_ip) {
                Ok(sender) => {
                    // Register AF_XDP socket in BPF xsk_map.
                    // try_lock() is safe here — called at init, no contention.
                    if let Ok(bpf_guard) = bpf.try_lock() {
                        if let Err(e) = bpf_guard.register_xsk_fd(sender.fd()) {
                            tracing::warn!(error = %e, "xsk_map registration failed");
                        }
                    }
                    Box::new(sender)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "hybrid sender unavailable — falling back to raw socket TX"
                    );
                    match RawSocketSender::new(src_ip, Some(iface)) {
                        Ok(s) => Box::new(s),
                        Err(e) => {
                            tracing::error!(error = %e, "raw socket fallback also failed");
                            return None;
                        }
                    }
                }
            }
        };

        let pacing = PacingProfile::Aggressive;
        let mut stealth = StealthProfile::linux_6x_default();
        pacing.apply_to(&mut stealth);

        Some(Arc::new(Mutex::new(SynScanner::new_with_sender(
            stealth, xdp_sender,
        ))))
    }

    /// Run a port discovery scan.
    ///
    /// Resolves DNS, expands ports, applies `max_ports` truncation, then
    /// dispatches to BPF SYN scanning or TCP connect-scan fallback.
    /// Returns `ScanResult` with `error` set on failure.
    pub async fn discover(&self, request: &crate::ScanRequest) -> ScanResult {
        let start = Instant::now();
        let (target_ip, target_hostname) = match resolve_target(&request.target) {
            Ok(r) => r,
            Err(e) => {
                return ScanResult {
                    request_id: request.request_id,
                    target_ip: Ipv4Addr::UNSPECIFIED,
                    target_hostname: None,
                    ports: vec![],
                    duration_ms: 0,
                    backend: self.backend_str().to_string(),
                    scanned_at: Utc::now(),
                    error: Some(e),
                };
            }
        };

        let mut ports = request.ports.expand();
        if let Some(max) = request.max_ports {
            ports.truncate(max as usize);
        }

        match self {
            Engine::Bpf(engine) => {
                engine
                    .discover_bpf(request, target_ip, target_hostname, &ports, start)
                    .await
            }
            Engine::ConnectOnly { .. } => {
                run_connect_scan(
                    target_ip,
                    &ports,
                    request.timeout_ms,
                    target_hostname,
                    request.request_id,
                )
                .await
            }
        }
    }

    /// Collect timing samples for a single port.
    ///
    /// BPF variant delegates to `collect_timing_samples_raw`. ConnectOnly
    /// returns an error (timing requires BPF kernel timestamps).
    pub async fn collect_timing(&self, request: &TimingRequest) -> TimingResult {
        match self {
            Engine::Bpf(engine) => {
                crate::timing::collect_timing_samples_raw(
                    request,
                    engine.collector.clone(),
                    engine.scanner.clone(),
                )
                .await
            }
            Engine::ConnectOnly { .. } => TimingResult::error(
                request,
                "BPF timing unavailable — connect-scan mode does not support RTT timing"
                    .to_string(),
            ),
        }
    }

    /// Backend string identifier.
    pub fn backend_str(&self) -> &str {
        match self {
            Engine::Bpf(engine) => engine.backend.as_str(),
            Engine::ConnectOnly { .. } => "connect",
        }
    }

    /// Network interface name.
    pub fn interface(&self) -> &str {
        match self {
            Engine::Bpf(engine) => &engine.interface,
            Engine::ConnectOnly { interface } => interface,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BPF discovery
// ─────────────────────────────────────────────────────────────────────────────

impl ScanEngine {
    /// BPF-backed port discovery: SYN batch send → early-return polling → collect.
    async fn discover_bpf(
        &self,
        request: &crate::ScanRequest,
        target_ip: Ipv4Addr,
        target_hostname: Option<String>,
        ports: &[u16],
        start: Instant,
    ) -> ScanResult {
        let batch_size = request.pacing.batch_size();
        let timeout_ms = request.timeout_ms;
        let timeout = Duration::from_millis(timeout_ms as u64);
        let target_ip_u32 = u32::from_be_bytes(target_ip.octets());

        // Apply per-request pacing to the shared scanner. We hold the lock
        // for the entire batch-send phase, so no concurrent access sees the
        // changed profile. Restored to Aggressive after sending.
        let mut scanner_guard = self.scanner.lock().await;
        let original_profile = scanner_guard.profile().clone();
        let mut scan_profile = StealthProfile::linux_6x_default();
        request.pacing.apply_to(&mut scan_profile);
        scanner_guard.set_profile(scan_profile);

        let mut all_probes = Vec::new();
        for batch in ports.chunks(batch_size) {
            let result = match scanner_guard.send_syn_batch(target_ip, batch) {
                Ok(r) => r,
                Err(e) => {
                    scanner_guard.set_profile(original_profile);
                    drop(scanner_guard);
                    return ScanResult {
                        request_id: request.request_id,
                        target_ip,
                        target_hostname,
                        ports: vec![],
                        duration_ms: start.elapsed().as_millis() as u64,
                        backend: self.backend.as_str().to_string(),
                        scanned_at: Utc::now(),
                        error: Some(format!("scan error: {e}")),
                    };
                }
            };
            all_probes.extend(result.probed_ports);

            // Drain AF_XDP RX ring between batches to prevent overflow
            scanner_guard.poll_rx(0);
        }

        // Restore Aggressive profile for timing probes
        scanner_guard.set_profile(original_profile);
        drop(scanner_guard);

        // Early-return polling: check every 5ms if all probes have responses.
        // Falls back to full timeout as the deadline.
        {
            let poll_interval = Duration::from_millis(5);
            let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms as u64);
            let total_probes = all_probes.len();

            loop {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline - now;
                tokio::time::sleep(poll_interval.min(remaining)).await;

                let bpf_guard = self.collector.lock().await;
                let responded = all_probes
                    .iter()
                    .filter(|probe| {
                        bpf_guard
                            .read_timing_v2(target_ip_u32, probe.dst_port, probe.src_port)
                            .is_some()
                    })
                    .count();
                drop(bpf_guard);

                if responded == total_probes {
                    break;
                }
            }
        }

        // Collect all results in one pass
        let collector = DiscoveryCollector::new(timeout);
        let bpf_guard = self.collector.lock().await;
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

        ScanResult {
            request_id: request.request_id,
            target_ip,
            target_hostname,
            ports: scanned_ports,
            duration_ms: start.elapsed().as_millis() as u64,
            backend: self.backend.as_str().to_string(),
            scanned_at: Utc::now(),
            error: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connect-scan fallback
// ─────────────────────────────────────────────────────────────────────────────

/// TCP connect-scan fallback when BPF is unavailable.
///
/// Uses tokio `TcpStream::connect` with 256-way concurrency. No kernel
/// timestamps — timing is userspace `Instant` only.
async fn run_connect_scan(
    target_ip: Ipv4Addr,
    ports: &[u16],
    timeout_ms: u32,
    target_hostname: Option<String>,
    request_id: Uuid,
) -> ScanResult {
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

    ScanResult {
        request_id,
        target_ip,
        target_hostname,
        ports: port_results,
        duration_ms: start.elapsed().as_millis() as u64,
        backend: "connect".to_string(),
        scanned_at: Utc::now(),
        error: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PortSpec, ScanRequest};

    // ── resolve_target ─────────────────────────────────────────────────────

    #[test]
    fn test_resolve_target_ipv4_literal() {
        let (ip, hostname) = resolve_target("192.168.1.1").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert!(hostname.is_none(), "IPv4 literal should not produce hostname");
    }

    #[test]
    fn test_resolve_target_returns_hostname_for_dns() {
        // localhost should resolve and return the hostname
        let result = resolve_target("localhost");
        if let Ok((_ip, hostname)) = result {
            assert_eq!(hostname.as_deref(), Some("localhost"));
        }
        // If localhost doesn't resolve (some CI), the test still passes
    }

    #[test]
    fn test_resolve_target_invalid_returns_error() {
        let result = resolve_target("this-host-does-not-exist-12345.invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DNS resolution failed"));
    }

    // ── Engine::ConnectOnly ────────────────────────────────────────────────

    #[test]
    fn test_connect_only_backend_str() {
        let engine = Engine::ConnectOnly {
            interface: "eth0".to_string(),
        };
        assert_eq!(engine.backend_str(), "connect");
    }

    #[test]
    fn test_connect_only_interface() {
        let engine = Engine::ConnectOnly {
            interface: "ens3".to_string(),
        };
        assert_eq!(engine.interface(), "ens3");
    }

    #[tokio::test]
    async fn test_connect_only_collect_timing_returns_error() {
        let engine = Engine::ConnectOnly {
            interface: "eth0".to_string(),
        };
        let request = TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: "127.0.0.1".to_string(),
            target_port: 80,
            sample_count: 5,
            timeout_ms: 1000,
            banner_timeout_ms: None,
        };
        let result = engine.collect_timing(&request).await;
        assert!(result.error.is_some());
        assert!(result.error.as_ref().unwrap().contains("BPF timing unavailable"));
        assert_eq!(result.precision_class, "error");
        assert!(result.samples.is_empty());
    }

    // ── max_ports truncation ───────────────────────────────────────────────

    #[test]
    fn test_max_ports_truncation() {
        let ports: Vec<u16> = (1..=100).collect();
        let mut truncated = ports.clone();
        let max_ports: Option<u32> = Some(10);
        if let Some(max) = max_ports {
            truncated.truncate(max as usize);
        }
        assert_eq!(truncated.len(), 10);
        assert_eq!(truncated, (1..=10).collect::<Vec<u16>>());
    }

    #[test]
    fn test_max_ports_none_no_truncation() {
        let ports: Vec<u16> = (1..=100).collect();
        let mut result = ports.clone();
        let max_ports: Option<u32> = None;
        if let Some(max) = max_ports {
            result.truncate(max as usize);
        }
        assert_eq!(result.len(), 100);
    }

    // ── ScanRequest with max_ports serde ───────────────────────────────────

    #[test]
    fn test_scan_request_max_ports_default() {
        let json = r#"{
            "request_id": "550e8400-e29b-41d4-a716-446655440000",
            "target": "10.0.0.1",
            "ports": "Full",
            "pacing": "normal",
            "timeout_ms": 2000
        }"#;
        let req: ScanRequest = serde_json::from_str(json).unwrap();
        assert!(req.max_ports.is_none());
    }

    #[test]
    fn test_scan_request_max_ports_set() {
        let json = r#"{
            "request_id": "550e8400-e29b-41d4-a716-446655440000",
            "target": "10.0.0.1",
            "ports": "Full",
            "pacing": "normal",
            "timeout_ms": 2000,
            "max_ports": 1024
        }"#;
        let req: ScanRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.max_ports, Some(1024));
    }

    // ── connect scan ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_connect_scan_returns_scan_result() {
        let request_id = Uuid::new_v4();
        // Scan a single port on localhost — likely closed or refused
        let result = run_connect_scan(
            Ipv4Addr::LOCALHOST,
            &[19999],
            500,
            None,
            request_id,
        )
        .await;
        assert_eq!(result.request_id, request_id);
        assert_eq!(result.target_ip, Ipv4Addr::LOCALHOST);
        assert_eq!(result.backend, "connect");
        assert!(result.error.is_none());
        assert_eq!(result.ports.len(), 1);
        // Port 19999 on localhost is almost certainly closed or filtered
        assert!(
            result.ports[0].state == PortState::Closed
                || result.ports[0].state == PortState::Filtered,
            "port 19999 on localhost should be closed or filtered, got {:?}",
            result.ports[0].state
        );
    }

    // ── Engine::discover with ConnectOnly ───────────────────────────────────

    #[tokio::test]
    async fn test_engine_discover_connect_only() {
        let engine = Engine::ConnectOnly {
            interface: "lo".to_string(),
        };
        let request = ScanRequest {
            request_id: Uuid::new_v4(),
            target: "127.0.0.1".to_string(),
            ports: PortSpec::Explicit(vec![19998]),
            pacing: PacingProfile::Aggressive,
            timeout_ms: 500,
            interface: None,
            max_ports: None,
        };
        let result = engine.discover(&request).await;
        assert_eq!(result.request_id, request.request_id);
        assert_eq!(result.target_ip, Ipv4Addr::LOCALHOST);
        assert_eq!(result.backend, "connect");
        assert!(result.error.is_none());
        assert_eq!(result.ports.len(), 1);
    }

    #[tokio::test]
    async fn test_engine_discover_dns_error() {
        let engine = Engine::ConnectOnly {
            interface: "lo".to_string(),
        };
        let request = ScanRequest {
            request_id: Uuid::new_v4(),
            target: "this-host-does-not-exist-12345.invalid".to_string(),
            ports: PortSpec::Explicit(vec![80]),
            pacing: PacingProfile::Normal,
            timeout_ms: 1000,
            interface: None,
            max_ports: None,
        };
        let result = engine.discover(&request).await;
        assert!(result.error.is_some());
        assert!(result.error.as_ref().unwrap().contains("DNS resolution failed"));
        assert!(result.ports.is_empty());
    }

    #[tokio::test]
    async fn test_engine_discover_max_ports_applied() {
        let engine = Engine::ConnectOnly {
            interface: "lo".to_string(),
        };
        let request = ScanRequest {
            request_id: Uuid::new_v4(),
            target: "127.0.0.1".to_string(),
            ports: PortSpec::Range { start: 19990, end: 19999 },
            pacing: PacingProfile::Aggressive,
            timeout_ms: 500,
            interface: None,
            max_ports: Some(3),
        };
        let result = engine.discover(&request).await;
        assert_eq!(result.ports.len(), 3, "max_ports=3 should truncate to 3 ports");
    }

    // ── Engine::new fallback ───────────────────────────────────────────────

    #[test]
    fn test_engine_new_returns_some_variant() {
        // On non-Linux or unprivileged, returns ConnectOnly.
        // On Linux with BPF, returns Bpf.
        // Either way, it must not panic.
        let engine = Engine::new(ScanEngineConfig {
            interface: None,
            passthrough: true,
        });
        // Just verify it doesn't panic and has a valid backend
        let backend = engine.backend_str();
        assert!(
            backend == "connect" || backend == "xdp" || backend == "xdp-hybrid",
            "backend must be one of connect/xdp/xdp-hybrid, got '{backend}'"
        );
    }
}
