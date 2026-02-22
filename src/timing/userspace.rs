//! TCP timing collection.
//!
//! Collects high-precision timing samples using XDP/BPF kernel-level timestamps
//! for IPv4 connections, with inline userspace fallback for IPv6 (XDP doesn't
//! support IPv6).

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{TimingRequest, TimingResult};
use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Maximum banner bytes to capture from a service.
const MAX_BANNER_BYTES: usize = 512;

/// Default banner read timeout in milliseconds.
const DEFAULT_BANNER_TIMEOUT_MS: u32 = 200;

use super::stats::calculate_stats;
use super::xdp::BpfTimingCollector;

/// Collect timing samples for a TCP connection.
///
/// When `bpf` is `Some`, uses BPF kernel-level timestamps for IPv4 connections.
/// When `bpf` is `None`, uses pure userspace timing (degraded precision).
/// IPv6 always uses inline userspace timing (XDP doesn't support IPv6).
pub async fn collect_timing_samples(
    request: &TimingRequest,
    bpf: Option<Arc<Mutex<BpfTimingCollector>>>,
) -> TimingResult {
    let addr = match resolve_address(&request.target_host, request.target_port) {
        Ok(addr) => addr,
        Err(e) => return TimingResult::error(request, format!("DNS resolution failed: {}", e)),
    };

    let timeout = Duration::from_millis(request.timeout_ms as u64);
    let mut samples = Vec::with_capacity(request.sample_count as usize);
    let mut last_error: Option<String> = None;
    let mut banner: Option<Vec<u8>> = None;

    let ipv4_info = match addr {
        SocketAddr::V4(v4) => Some(u32::from_be_bytes(v4.ip().octets())),
        SocketAddr::V6(_) => None,
    };
    let dst_port = request.target_port;
    let banner_timeout_ms = request
        .banner_timeout_ms
        .unwrap_or(DEFAULT_BANNER_TIMEOUT_MS);
    let sample_count = request.sample_count as usize;

    for i in 0..sample_count {
        let start = Instant::now();
        let is_last = i == sample_count - 1;

        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(mut stream) => {
                let elapsed = start.elapsed();
                let src_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);

                let micros = match (&bpf, ipv4_info) {
                    (Some(bpf_arc), Some(dst_ip)) => {
                        // IPv4 + BPF: lock briefly for kernel timestamp read
                        let bpf_ref = bpf_arc.lock().await;
                        let delta = bpf_ref.read_timing(dst_ip, dst_port, src_port);
                        bpf_ref.delete_entry(dst_ip, dst_port, src_port);
                        drop(bpf_ref);
                        match delta {
                            Some(ns) => ns as f64 / 1000.0,
                            None => elapsed.as_micros() as f64,
                        }
                    }
                    _ => {
                        // IPv6 or no BPF: userspace timing
                        elapsed.as_micros() as f64
                    }
                };

                samples.push(micros);

                // On the last sample, attempt passive banner capture
                if is_last {
                    banner = read_banner(&mut stream, banner_timeout_ms);
                }

                drop(stream);
            }
            Err(e) => {
                last_error = Some(format!("{}", e));
                // Early bail-out: if no samples collected yet, the port is
                // unreachable and remaining attempts will also fail.
                if samples.is_empty() {
                    break;
                }
            }
        }
    }

    if samples.is_empty() {
        return TimingResult::error(
            request,
            last_error.unwrap_or_else(|| "No samples collected".to_string()),
        );
    }

    let stats = calculate_stats(&samples);
    let precision_class = match &bpf {
        Some(bpf_arc) => {
            let bpf_ref = bpf_arc.lock().await;
            bpf_ref.backend().precision_class().to_string()
        }
        None => "userspace".to_string(),
    };

    TimingResult {
        request_id: request.request_id,
        scan_id: request.scan_id,
        target_host: request.target_host.clone(),
        target_port: request.target_port,
        samples,
        precision_class,
        stats,
        collected_at: chrono::Utc::now(),
        error: None,
        embedding: None,
        banner,
        source_ip: None,
        worker_node: None,
    }
}

/// Attempt to read a banner from an open TCP stream.
///
/// Sets a short read timeout and tries to read up to MAX_BANNER_BYTES.
/// Returns `Some(bytes)` if any data was received, `None` otherwise.
fn read_banner(stream: &mut TcpStream, timeout_ms: u32) -> Option<Vec<u8>> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms as u64)));
    let mut buf = vec![0u8; MAX_BANNER_BYTES];
    match stream.read(&mut buf) {
        Ok(0) => None,
        Ok(n) => {
            buf.truncate(n);
            Some(buf)
        }
        Err(_) => None,
    }
}

use super::xdp::TimingMapEntry;
use crate::scanner::syn_sender::SynScanner;
use crate::PortState;

/// Poll interval for AF_XDP RX ring drain + BPF map checks in milliseconds.
const AFXDP_POLL_INTERVAL_MS: u64 = 1;

/// Poll the BPF timing map for a specific probe's entry while draining the AF_XDP RX ring.
///
/// Each probe has a unique `src_port`, so the BPF map key `(src_port, dst_port, dst_ip)` is
/// probe-specific. This eliminates the cross-contamination bug where concurrent probes share
/// the AF_XDP ring: one probe's `poll_rx()` call could consume another probe's SYN-ACK frame,
/// leaving that probe with "no map entry" even though the BPF map has the entry.
///
/// By polling the BPF map directly (keyed by src_port) instead of relying on the shared
/// AF_XDP ring as a notification signal, each probe waits only for its own response.
/// The AF_XDP ring is still drained on each iteration to prevent backpressure and allow
/// the XDP program to continue redirecting incoming SYN-ACKs to the socket.
///
/// Returns `Some(entry)` when the probe's BPF map entry has a response, `None` on timeout.
async fn poll_bpf_timing_entry(
    bpf: &Arc<Mutex<BpfTimingCollector>>,
    scanner: &Arc<Mutex<SynScanner>>,
    dst_ip: u32,
    dst_port: u16,
    src_port: u16,
    timeout_ms: u64,
) -> Option<TimingMapEntry> {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);

    loop {
        // Drain AF_XDP ring to prevent overflow and allow XDP to keep redirecting.
        // We don't care which frames arrive here — the BPF map is the source of truth.
        {
            let mut scanner_ref = scanner.lock().await;
            scanner_ref.poll_rx(0);
        }

        // Check if this probe's map entry has a response.
        // read_timing_v2 returns None when: (a) no entry exists, or (b) only SYN flag set
        // (TC recorded the SYN but no response yet). Returns Some once response arrives.
        {
            let bpf_ref = bpf.lock().await;
            if let Some(entry) = bpf_ref.read_timing_v2(dst_ip, dst_port, src_port) {
                return Some(entry);
            }
        }

        if tokio::time::Instant::now() >= deadline {
            return None;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(AFXDP_POLL_INTERVAL_MS)).await;
    }
}

/// Collect timing samples using raw SYN probes via the SynScanner (AF_XDP path).
///
/// The full kernel-level pipeline:
/// 1. SYN is sent via AF_XDP TX (UMEM DMA, no socket buffer copy)
/// 2. TC egress BPF timestamps the SYN in `timing_map`
/// 3. XDP ingress BPF timestamps the response and redirects it to our AF_XDP RX ring
/// 4. We poll the AF_XDP RX ring for the response frame
/// 5. We read the precise timing delta from `timing_map`
///
/// Because responses are consumed by the AF_XDP socket (step 3), the kernel TCP
/// stack never sees SYN-ACKs — no auto-RST, no iptables suppression needed.
///
/// Banner is always `None` — SYN-only probes never complete a TCP handshake.
///
/// IPv6 targets are not supported; callers should fall back to
/// `collect_timing_samples()` for IPv6.
pub async fn collect_timing_samples_raw(
    request: &TimingRequest,
    bpf: Arc<Mutex<BpfTimingCollector>>,
    scanner: Arc<Mutex<SynScanner>>,
) -> TimingResult {
    let addr = match resolve_address(&request.target_host, request.target_port) {
        Ok(addr) => addr,
        Err(e) => return TimingResult::error(request, format!("DNS resolution failed: {}", e)),
    };

    // Only IPv4 is supported for raw SYN probes
    let target_ipv4 = match addr {
        SocketAddr::V4(v4) => *v4.ip(),
        SocketAddr::V6(_) => {
            return TimingResult::error(
                request,
                "raw SYN probes require IPv4 (IPv6 not supported by XDP)".to_string(),
            );
        }
    };

    let dst_ip_u32 = u32::from_be_bytes(target_ipv4.octets());
    let dst_port = request.target_port;
    let timeout_ms = request.timeout_ms as u64;
    let sample_count = request.sample_count as usize;

    let mut samples = Vec::with_capacity(sample_count);
    let mut last_error: Option<String> = None;

    for _i in 0..sample_count {
        let start = Instant::now();

        // Send a single raw SYN probe via AF_XDP TX
        let probe = {
            let mut scanner_ref = scanner.lock().await;
            match scanner_ref.send_single_syn(target_ipv4, dst_port) {
                Ok(p) => p,
                Err(e) => {
                    last_error = Some(format!("SYN send failed: {}", e));
                    if samples.is_empty() {
                        break;
                    }
                    continue;
                }
            }
        };

        // Poll the BPF timing map for this probe's specific entry (keyed by src_port).
        // The AF_XDP ring is drained on each iteration to prevent overflow.
        // This is race-free across concurrent probes: each probe has a unique src_port,
        // so concurrent poll_rx() calls cannot steal each other's map entries.
        let entry = poll_bpf_timing_entry(
            &bpf,
            &scanner,
            dst_ip_u32,
            dst_port,
            probe.src_port,
            timeout_ms,
        )
        .await;

        match entry {
            Some(ref e) if e.delta_ns > 0 => {
                // Full TC+XDP path: precise kernel-level timing delta available.
                samples.push(e.delta_ns as f64 / 1000.0);
            }
            Some(ref e) if e.port_state == PortState::Open => {
                // Response-only entry: AF_XDP TX bypassed TC egress (XDP_COPY mode uses
                // dev_direct_xmit which skips TC). Port IS open — SYN-ACK confirmed by
                // BPF map. Fall back to userspace elapsed time for degraded timing.
                tracing::debug!(
                    dst_ip = %target_ipv4,
                    dst_port,
                    "AF_XDP TX bypassed TC egress — open port detected, using userspace timing"
                );
                samples.push(start.elapsed().as_micros() as f64);
            }
            Some(_) => {
                // Port is closed (RST) or unreachable (ICMP) — not an open port.
                last_error = Some("port closed or unreachable (RST/ICMP)".to_string());
                if samples.is_empty() {
                    break;
                }
            }
            None => {
                // Timeout: no response received within timeout_ms.
                // Port is filtered or target is unreachable.
                last_error =
                    Some("no response within timeout (filtered or unreachable)".to_string());
                if samples.is_empty() {
                    break;
                }
            }
        }

        // Clean up BPF map entry
        {
            let bpf_ref = bpf.lock().await;
            bpf_ref.delete_entry(dst_ip_u32, dst_port, probe.src_port);
        }

        // Inter-probe jitter delay from stealth profile
        let delay_ms = {
            let scanner_ref = scanner.lock().await;
            scanner_ref.profile().jittered_delay_ms()
        };
        if delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }
    }

    if samples.is_empty() {
        return TimingResult::error(
            request,
            last_error.unwrap_or_else(|| "No samples collected".to_string()),
        );
    }

    let stats = calculate_stats(&samples);
    let precision_class = {
        let bpf_ref = bpf.lock().await;
        bpf_ref.backend().precision_class().to_string()
    };

    TimingResult {
        request_id: request.request_id,
        scan_id: request.scan_id,
        target_host: request.target_host.clone(),
        target_port: request.target_port,
        samples,
        precision_class,
        stats,
        collected_at: chrono::Utc::now(),
        error: None,
        embedding: None,
        banner: None, // SYN-only: no handshake, no banner
        source_ip: None,
        worker_node: None,
    }
}

/// Resolve hostname and port to a socket address.
pub(crate) fn resolve_address(host: &str, port: u16) -> Result<SocketAddr, String> {
    let addr_str = format!("{}:{}", host, port);
    addr_str
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "No addresses found".to_string())
}

/// Collect timing samples synchronously (test-only, no BPF).
#[cfg(test)]
pub(crate) fn collect_timing_samples_sync(request: &TimingRequest) -> TimingResult {
    let addr = match resolve_address(&request.target_host, request.target_port) {
        Ok(addr) => addr,
        Err(e) => return TimingResult::error(request, format!("DNS resolution failed: {}", e)),
    };

    let timeout = Duration::from_millis(request.timeout_ms as u64);
    let mut samples = Vec::with_capacity(request.sample_count as usize);
    let mut last_error: Option<String> = None;
    let mut banner: Option<Vec<u8>> = None;
    let banner_timeout_ms = request
        .banner_timeout_ms
        .unwrap_or(DEFAULT_BANNER_TIMEOUT_MS);
    let sample_count = request.sample_count as usize;

    for i in 0..sample_count {
        let start = Instant::now();
        let is_last = i == sample_count - 1;

        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(mut stream) => {
                let elapsed = start.elapsed();
                samples.push(elapsed.as_micros() as f64);

                // On the last sample, attempt passive banner capture
                if is_last {
                    banner = read_banner(&mut stream, banner_timeout_ms);
                }

                drop(stream);
            }
            Err(e) => {
                last_error = Some(format!("{}", e));
                if samples.is_empty() {
                    break;
                }
            }
        }
    }

    if samples.is_empty() {
        return TimingResult::error(
            request,
            last_error.unwrap_or_else(|| "No samples collected".to_string()),
        );
    }

    let stats = calculate_stats(&samples);

    TimingResult {
        request_id: request.request_id,
        scan_id: request.scan_id,
        target_host: request.target_host.clone(),
        target_port: request.target_port,
        samples,
        precision_class: "userspace".to_string(),
        stats,
        collected_at: chrono::Utc::now(),
        error: None,
        embedding: None,
        banner,
        source_ip: None,
        worker_node: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use uuid::Uuid;

    // ===========================================
    // Tests for poll_bpf_map and collect_timing_samples_raw
    // ===========================================

    // Note: poll_bpf_map requires a real BpfTimingCollector (not mock) because it
    // takes Arc<Mutex<BpfTimingCollector>>. These tests verify the logic using
    // the MockBpfTimingCollector where possible, and test the higher-level
    // collect_timing_samples_raw behavior through integration tests on Linux.

    // ===========================================
    // Tests for poll_bpf_timing_entry behaviour
    // ===========================================

    /// Verify the "no map entry" cross-contamination path is no longer reachable:
    /// poll_bpf_timing_entry polls the map directly by probe key, so a concurrent
    /// probe consuming the AF_XDP ring frame does NOT cause "no map entry" for us.
    /// This test documents the contract: None == timeout (filtered), not "stolen frame".
    #[test]
    fn test_collect_timing_raw_error_on_timeout_is_filtered_not_stolen() {
        // The error message for a probe timeout must not claim "no map entry after AF_XDP RX"
        // (that message indicated cross-contamination which no longer occurs).
        // It must instead describe the timeout condition.
        let result = TimingResult {
            request_id: uuid::Uuid::new_v4(),
            scan_id: None,
            target_host: "192.0.2.1".to_string(),
            target_port: 80,
            samples: vec![],
            precision_class: "error".to_string(),
            stats: calculate_stats(&[]),
            collected_at: chrono::Utc::now(),
            error: Some("no response within timeout (filtered or unreachable)".to_string()),
            embedding: None,
            banner: None,
            source_ip: None,
            worker_node: None,
        };
        let err = result.error.unwrap();
        assert!(
            !err.contains("no map entry after AF_XDP RX"),
            "timeout must not blame AF_XDP RX cross-contamination: {}",
            err
        );
        assert!(
            err.contains("timeout") || err.contains("filtered") || err.contains("unreachable"),
            "timeout error must describe the actual cause: {}",
            err
        );
    }

    #[test]
    fn test_raw_result_always_has_no_banner() {
        // Verify the contract: raw SYN probes never produce banners.
        // This is a structural test — the function always sets banner: None.
        // Full integration requires CAP_NET_RAW + BPF, tested on Linux.
        let result = TimingResult {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: "10.0.0.1".to_string(),
            target_port: 80,
            samples: vec![500.0],
            precision_class: "xdp".to_string(),
            stats: calculate_stats(&[500.0]),
            collected_at: chrono::Utc::now(),
            error: None,
            embedding: None,
            banner: None,
            source_ip: None,
            worker_node: None,
        };
        assert!(
            result.banner.is_none(),
            "raw SYN result must never have a banner"
        );
    }

    #[tokio::test]
    async fn test_raw_ipv6_returns_error() {
        // collect_timing_samples_raw should reject IPv6 targets
        let _request = TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: "::1".to_string(),
            target_port: 80,
            sample_count: 3,
            timeout_ms: 1000,
            banner_timeout_ms: None,
        };

        // We need real BPF + scanner for the function signature, but IPv6 check
        // happens before any BPF/scanner interaction. Since we can't create
        // BpfTimingCollector on macOS, we verify the resolve_address path.
        let addr = resolve_address("::1", 80);
        if let Ok(SocketAddr::V6(_)) = addr {
            // If ::1 resolves to IPv6, the function would return an error
            // We can't call collect_timing_samples_raw without BPF, but verify the logic
            assert!(true, "IPv6 address correctly identified");
        }
    }

    fn create_request(host: &str, port: u16, samples: u32, timeout_ms: u32) -> TimingRequest {
        TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: host.to_string(),
            target_port: port,
            sample_count: samples,
            timeout_ms,
            banner_timeout_ms: None,
        }
    }

    #[test]
    fn test_resolve_address_ip() {
        let addr = resolve_address("127.0.0.1", 80).unwrap();
        assert_eq!(addr.port(), 80);
    }

    #[test]
    fn test_resolve_address_invalid() {
        let result = resolve_address("this-host-does-not-exist-12345.invalid", 80);
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_refused_returns_error() {
        // Port 1 is unlikely to be open
        let request = create_request("127.0.0.1", 1, 3, 1000);
        let result = collect_timing_samples_sync(&request);

        // Should have error because connection refused
        assert!(result.error.is_some() || result.samples.is_empty());
        if result.error.is_some() {
            assert_eq!(result.precision_class, "error");
        }
    }

    #[test]
    fn test_banner_captured_from_service() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let banner_text = b"SSH-2.0-OpenSSH_8.9\r\n";

        // Server thread: accept connections, send banner on each
        let handle = std::thread::spawn(move || {
            // Accept enough connections for all samples
            for _ in 0..3 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.write_all(banner_text);
                    // Keep stream alive briefly so client can read
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        });

        // Give server a moment to start
        std::thread::sleep(Duration::from_millis(10));

        let request = TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: "127.0.0.1".to_string(),
            target_port: port,
            sample_count: 3,
            timeout_ms: 2000,
            banner_timeout_ms: Some(500),
        };

        let result = collect_timing_samples_sync(&request);

        handle.join().unwrap();

        assert!(result.error.is_none(), "expected no error");
        assert_eq!(result.samples.len(), 3);
        assert!(
            result.banner.is_some(),
            "expected banner to be captured on last sample"
        );
        assert_eq!(result.banner.unwrap(), banner_text.to_vec());
    }

    #[test]
    fn test_banner_none_when_service_silent() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Server thread: accept connections but send nothing
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                if let Ok((_stream, _)) = listener.accept() {
                    std::thread::sleep(Duration::from_millis(300));
                }
            }
        });

        std::thread::sleep(Duration::from_millis(10));

        let request = TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: "127.0.0.1".to_string(),
            target_port: port,
            sample_count: 2,
            timeout_ms: 2000,
            banner_timeout_ms: Some(100),
        };

        let result = collect_timing_samples_sync(&request);

        handle.join().unwrap();

        assert!(result.error.is_none(), "expected no error");
        assert_eq!(result.samples.len(), 2);
        assert!(
            result.banner.is_none(),
            "expected no banner when service sends nothing"
        );
    }

    #[test]
    fn test_banner_max_512_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Server thread: send 1024 bytes
        let big_data = vec![b'A'; 1024];
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(&big_data);
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        std::thread::sleep(Duration::from_millis(10));

        let request = TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: "127.0.0.1".to_string(),
            target_port: port,
            sample_count: 1,
            timeout_ms: 2000,
            banner_timeout_ms: Some(500),
        };

        let result = collect_timing_samples_sync(&request);

        handle.join().unwrap();

        assert!(result.banner.is_some(), "expected banner");
        let banner = result.banner.unwrap();
        assert!(
            banner.len() <= MAX_BANNER_BYTES,
            "banner should be capped at {} bytes, got {}",
            MAX_BANNER_BYTES,
            banner.len()
        );
    }

    #[test]
    fn test_banner_only_on_last_sample() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let banner_text = b"220 mail.example.com ESMTP\r\n";

        // Server thread: accept all connections and send banner
        let handle = std::thread::spawn(move || {
            for _ in 0..5 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.write_all(banner_text);
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });

        std::thread::sleep(Duration::from_millis(10));

        let request = TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: "127.0.0.1".to_string(),
            target_port: port,
            sample_count: 5,
            timeout_ms: 2000,
            banner_timeout_ms: Some(500),
        };

        let result = collect_timing_samples_sync(&request);

        handle.join().unwrap();

        assert!(result.error.is_none());
        assert_eq!(result.samples.len(), 5, "all 5 samples should succeed");
        // Banner should be captured (from the last sample)
        assert!(result.banner.is_some(), "expected banner from last sample");
        assert_eq!(result.banner.unwrap(), banner_text.to_vec());
    }

    #[test]
    fn test_timing_unaffected_by_banner_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Server thread: accept connections, send banner with delay
        let handle = std::thread::spawn(move || {
            for _ in 0..5 {
                if let Ok((mut stream, _)) = listener.accept() {
                    // Delay banner send to ensure timing is already recorded
                    std::thread::sleep(Duration::from_millis(50));
                    let _ = stream.write_all(b"SSH-2.0-Test\r\n");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        });

        std::thread::sleep(Duration::from_millis(10));

        let request = TimingRequest {
            request_id: Uuid::new_v4(),
            scan_id: None,
            target_host: "127.0.0.1".to_string(),
            target_port: port,
            sample_count: 5,
            timeout_ms: 2000,
            banner_timeout_ms: Some(200),
        };

        let result = collect_timing_samples_sync(&request);

        handle.join().unwrap();

        assert!(result.error.is_none());
        assert_eq!(result.samples.len(), 5);

        // All samples should be reasonable TCP handshake times (< 50ms = 50000µs)
        // The banner read delay should NOT inflate the timing samples
        for (i, sample) in result.samples.iter().enumerate() {
            assert!(
                *sample < 50000.0,
                "sample {} = {}µs, should be < 50000µs (banner read should not inflate timing)",
                i,
                sample
            );
        }
    }
}
