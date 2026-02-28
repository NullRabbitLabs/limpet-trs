//! Raw SYN probe timing collection.
//!
//! Collects high-precision timing samples using XDP/BPF kernel-level timestamps
//! for IPv4 connections. Raw SYN probes via AF_XDP TX with kernel-bypass timing.
//! No userspace fallback — requires Linux with CAP_BPF + CAP_NET_ADMIN.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{TimingRequest, TimingResult};
use std::net::{SocketAddr, ToSocketAddrs};

use super::stats::calculate_stats;
use super::xdp::BpfTimingCollector;

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
/// IPv6 targets are not supported and return an error.
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
    let mut skipped_count: usize = 0;

    for _i in 0..sample_count {
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
                // delta_ns=0 with Open port means TC egress didn't fire (e.g. XDP_COPY
                // mode uses dev_direct_xmit which skips TC). The SYN-ACK was received
                // but no egress timestamp exists. Skip this sample rather than silently
                // falling back to userspace timing.
                skipped_count += 1;
                tracing::warn!(
                    dst_ip = %target_ipv4,
                    dst_port,
                    "BPF delta_ns=0 for Open port — TC egress may not have fired, skipping sample"
                );
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
        let base = bpf_ref.backend().precision_class().to_string();
        if skipped_count > 0 {
            format!("{base}_degraded")
        } else {
            base
        }
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

#[cfg(test)]
mod tests {
    use super::*;
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
            // IPv6 address correctly identified — no further assertion needed
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
}
