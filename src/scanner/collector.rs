//! Discovery result collector.
//!
//! Polls the BPF map after SYN probes complete, classifies ports by response
//! type, and cleans up map entries. Promotes unanswered probes to Filtered
//! after timeout.

use std::time::{Duration, Instant};

use crate::timing::xdp::{BpfReader, TimingMapEntry};
use crate::timing::MockBpfTimingCollector;
use crate::PortState;

use super::syn_sender::ProbeRecord;

/// Classification of a discovered port.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredPort {
    /// Port number.
    pub port: u16,
    /// Port state from discovery.
    pub state: PortState,
    /// SYN-to-response timing in nanoseconds (0 for filtered/timeout).
    pub timing_ns: u64,
    /// IP TTL from response (0 if no response).
    pub response_ttl: u8,
    /// TCP window from response (0 if no response or ICMP).
    pub response_win: u16,
    /// Source port used for the probe.
    pub src_port: u16,
}

/// Result of a discovery collection pass.
#[derive(Debug)]
pub struct DiscoveryBatch {
    /// All discovered ports with classifications.
    pub ports: Vec<DiscoveredPort>,
    /// Number of open ports found.
    pub open_count: usize,
    /// Number of closed ports found.
    pub closed_count: usize,
    /// Number of unreachable ports found.
    pub unreachable_count: usize,
    /// Number of filtered (timeout) ports.
    pub filtered_count: usize,
    /// Number of ports reclassified as firewalled (RST from middlebox).
    pub firewalled_count: usize,
}

/// Collects discovery results from the BPF map using a mock collector.
///
/// In production, the real BpfTimingCollector is used via the same interface.
/// This collector works with any type that provides `read_timing_v2()` and
/// `delete_entry()`.
pub struct DiscoveryCollector {
    timeout: Duration,
}

impl DiscoveryCollector {
    /// Create a new collector with the specified probe timeout.
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Collect results for a batch of probes using the mock BPF collector.
    ///
    /// Reads each probe's entry from the BPF map, classifies the port,
    /// promotes Pending entries to Filtered if past timeout, and cleans
    /// up all entries.
    pub fn collect_from_mock(
        &self,
        probes: &[ProbeRecord],
        bpf: &MockBpfTimingCollector,
        target_ip: u32,
    ) -> DiscoveryBatch {
        let now = Instant::now();
        let mut ports = Vec::with_capacity(probes.len());
        let mut open_count = 0;
        let mut closed_count = 0;
        let mut unreachable_count = 0;
        let mut filtered_count = 0;

        for probe in probes {
            let entry = bpf.read_timing_v2(target_ip, probe.dst_port, probe.src_port);
            let discovered = self.classify_probe(probe, entry, now);

            match discovered.state {
                PortState::Open => open_count += 1,
                PortState::Closed => closed_count += 1,
                PortState::Unreachable => unreachable_count += 1,
                PortState::Filtered => filtered_count += 1,
                PortState::Pending => filtered_count += 1, // shouldn't happen after classify
                PortState::Firewalled => {}                // counted after reclassify pass
            }

            ports.push(discovered);

            // Cleanup BPF map entry
            bpf.delete_entry(target_ip, probe.dst_port, probe.src_port);
        }

        let mut batch = DiscoveryBatch {
            ports,
            open_count,
            closed_count,
            unreachable_count,
            filtered_count,
            firewalled_count: 0,
        };
        reclassify_firewalled(&mut batch);
        batch
    }

    /// Collect results for a batch of probes using any BpfReader implementation.
    ///
    /// Generic version of `collect_from_mock` that works with both the real
    /// `BpfTimingCollector` and `MockBpfTimingCollector`.
    pub fn collect<B: BpfReader>(
        &self,
        probes: &[ProbeRecord],
        bpf: &B,
        target_ip: u32,
    ) -> DiscoveryBatch {
        let now = Instant::now();
        let mut ports = Vec::with_capacity(probes.len());
        let mut open_count = 0;
        let mut closed_count = 0;
        let mut unreachable_count = 0;
        let mut filtered_count = 0;

        for probe in probes {
            let entry = bpf.read_timing_v2(target_ip, probe.dst_port, probe.src_port);
            let discovered = self.classify_probe(probe, entry, now);

            match discovered.state {
                PortState::Open => open_count += 1,
                PortState::Closed => closed_count += 1,
                PortState::Unreachable => unreachable_count += 1,
                PortState::Filtered => filtered_count += 1,
                PortState::Pending => filtered_count += 1,
                PortState::Firewalled => {} // counted after reclassify pass
            }

            ports.push(discovered);

            bpf.delete_entry(target_ip, probe.dst_port, probe.src_port);
        }

        let mut batch = DiscoveryBatch {
            ports,
            open_count,
            closed_count,
            unreachable_count,
            filtered_count,
            firewalled_count: 0,
        };
        reclassify_firewalled(&mut batch);
        batch
    }

    /// Classify a single probe based on its BPF map entry.
    fn classify_probe(
        &self,
        probe: &ProbeRecord,
        entry: Option<TimingMapEntry>,
        now: Instant,
    ) -> DiscoveredPort {
        match entry {
            Some(e) if e.port_state == PortState::Open => DiscoveredPort {
                port: probe.dst_port,
                state: PortState::Open,
                timing_ns: e.delta_ns,
                response_ttl: e.response_ttl,
                response_win: e.response_win,
                src_port: probe.src_port,
            },
            Some(e) if e.port_state == PortState::Closed => DiscoveredPort {
                port: probe.dst_port,
                state: PortState::Closed,
                timing_ns: e.delta_ns,
                response_ttl: e.response_ttl,
                response_win: e.response_win,
                src_port: probe.src_port,
            },
            Some(e) if e.port_state == PortState::Unreachable => DiscoveredPort {
                port: probe.dst_port,
                state: PortState::Unreachable,
                timing_ns: e.delta_ns,
                response_ttl: e.response_ttl,
                response_win: e.response_win,
                src_port: probe.src_port,
            },
            Some(e) if e.port_state == PortState::Pending => {
                // Still pending — check if past timeout
                if now.duration_since(probe.sent_at) >= self.timeout {
                    DiscoveredPort {
                        port: probe.dst_port,
                        state: PortState::Filtered,
                        timing_ns: 0,
                        response_ttl: 0,
                        response_win: 0,
                        src_port: probe.src_port,
                    }
                } else {
                    DiscoveredPort {
                        port: probe.dst_port,
                        state: PortState::Pending,
                        timing_ns: e.delta_ns,
                        response_ttl: 0,
                        response_win: 0,
                        src_port: probe.src_port,
                    }
                }
            }
            None => {
                // No entry at all — treat as filtered
                DiscoveredPort {
                    port: probe.dst_port,
                    state: PortState::Filtered,
                    timing_ns: 0,
                    response_ttl: 0,
                    response_win: 0,
                    src_port: probe.src_port,
                }
            }
            // Catch-all for any other state
            Some(e) => DiscoveredPort {
                port: probe.dst_port,
                state: e.port_state,
                timing_ns: e.delta_ns,
                response_ttl: e.response_ttl,
                response_win: e.response_win,
                src_port: probe.src_port,
            },
        }
    }
}

/// Reclassify Closed (RST) ports as Firewalled when the RST fingerprint
/// indicates a middlebox rather than the real host.
///
/// Signals (either triggers reclassification):
/// - TTL: `rst_ttl > baseline_ttl + 5` (RST from fewer hops → closer origin)
/// - Timing: `rst_timing_ns < baseline_timing_ns * 0.2` AND `rst_timing_ns < 500_000ns`
///
/// If no Open ports are available, only the absolute timing threshold applies.
fn reclassify_firewalled(batch: &mut DiscoveryBatch) {
    // Build baseline from Open ports
    let open_ports: Vec<&DiscoveredPort> = batch
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .collect();

    let baseline_ttl: Option<u8> = if open_ports.is_empty() {
        None
    } else {
        // Mode of Open TTLs
        let mut counts = [0u32; 256];
        for p in &open_ports {
            counts[p.response_ttl as usize] += 1;
        }
        counts
            .iter()
            .enumerate()
            .max_by_key(|(_, &c)| c)
            .map(|(i, _)| i as u8)
    };

    let baseline_timing_ns: Option<u64> = if open_ports.is_empty() {
        None
    } else {
        // Median of Open timings
        let mut timings: Vec<u64> = open_ports.iter().map(|p| p.timing_ns).collect();
        timings.sort_unstable();
        let mid = timings.len() / 2;
        Some(timings[mid])
    };

    const ABSOLUTE_TIMING_THRESHOLD_NS: u64 = 500_000; // 500µs

    for port in batch.ports.iter_mut() {
        if port.state != PortState::Closed {
            continue;
        }

        let ttl_signal = baseline_ttl
            .map(|bl| port.response_ttl > bl.saturating_add(5))
            .unwrap_or(false);

        let timing_signal = match baseline_timing_ns {
            Some(bl) => port.timing_ns < bl / 5 && port.timing_ns < ABSOLUTE_TIMING_THRESHOLD_NS,
            None => port.timing_ns < ABSOLUTE_TIMING_THRESHOLD_NS,
        };

        if ttl_signal || timing_signal {
            port.state = PortState::Firewalled;
            batch.firewalled_count += 1;
            batch.closed_count -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimingBackend;

    fn make_probe(dst_port: u16, src_port: u16) -> ProbeRecord {
        ProbeRecord {
            dst_port,
            src_port,
            sent_at: Instant::now(),
            isn: 0,
        }
    }

    fn make_old_probe(dst_port: u16, src_port: u16, age: Duration) -> ProbeRecord {
        ProbeRecord {
            dst_port,
            src_port,
            sent_at: Instant::now() - age,
            isn: 0,
        }
    }

    #[test]
    fn test_collector_open_port() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 500_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(80, 50000)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.open_count, 1);
        assert_eq!(result.ports[0].state, PortState::Open);
        assert_eq!(result.ports[0].timing_ns, 500_000);
        assert_eq!(result.ports[0].response_ttl, 64);
        assert_eq!(result.ports[0].response_win, 65535);
    }

    #[test]
    fn test_collector_closed_port() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        // RST arrives in 2ms — above the 500µs absolute firewalled threshold,
        // so this stays Closed (no open-port baseline available).
        bpf.add_entry_v2(
            target_ip,
            22,
            50001,
            TimingMapEntry {
                delta_ns: 2_000_000, // 2ms — genuine host RST
                port_state: PortState::Closed,
                response_ttl: 64,
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(22, 50001)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.closed_count, 1);
        assert_eq!(result.ports[0].state, PortState::Closed);
    }

    #[test]
    fn test_collector_unreachable_port() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            443,
            50002,
            TimingMapEntry {
                delta_ns: 300_000,
                port_state: PortState::Unreachable,
                response_ttl: 252,
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(443, 50002)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.unreachable_count, 1);
        assert_eq!(result.ports[0].state, PortState::Unreachable);
        assert_eq!(result.ports[0].response_ttl, 252);
    }

    #[test]
    fn test_collector_filtered_timeout() {
        // No BPF entry at all → filtered
        let bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(8080, 50003)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.filtered_count, 1);
        assert_eq!(result.ports[0].state, PortState::Filtered);
        assert_eq!(result.ports[0].timing_ns, 0);
    }

    #[test]
    fn test_collector_timing_samples_for_open() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 1_234_567,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 64240,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(80, 50000)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.ports[0].timing_ns, 1_234_567);
    }

    #[test]
    fn test_pending_entry_becomes_filtered_after_timeout() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        // Entry exists but still Pending (SYN sent, no response)
        bpf.add_entry_v2(
            target_ip,
            25,
            50004,
            TimingMapEntry {
                delta_ns: 0,
                port_state: PortState::Pending,
                response_ttl: 0,
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(2));
        // Probe sent 3 seconds ago (past 2s timeout)
        let probes = vec![make_old_probe(25, 50004, Duration::from_secs(3))];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.ports[0].state, PortState::Filtered);
    }

    #[test]
    fn test_pending_entry_stays_pending_before_timeout() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            25,
            50004,
            TimingMapEntry {
                delta_ns: 0,
                port_state: PortState::Pending,
                response_ttl: 0,
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(10));
        // Probe sent just now (well within 10s timeout)
        let probes = vec![make_probe(25, 50004)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.ports[0].state, PortState::Pending);
    }

    #[test]
    fn test_bpf_map_cleanup_after_discovery() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 500_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );
        bpf.add_entry_v2(
            target_ip,
            443,
            50001,
            TimingMapEntry {
                delta_ns: 600_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(80, 50000), make_probe(443, 50001)];
        let _result = collector.collect_from_mock(&probes, &bpf, target_ip);

        let deleted = bpf.deleted_entries();
        assert_eq!(deleted.len(), 2, "all probed entries must be cleaned up");
    }

    // ===========================================
    // Stage 5 Tests: Generic collect method
    // ===========================================

    #[test]
    fn test_generic_collect_matches_collect_from_mock() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 500_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );
        bpf.add_entry_v2(
            target_ip,
            22,
            50001,
            TimingMapEntry {
                delta_ns: 200_000,
                port_state: PortState::Closed,
                response_ttl: 64,
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(80, 50000), make_probe(22, 50001)];
        let result = collector.collect(&probes, &bpf, target_ip);

        assert_eq!(result.open_count, 1);
        assert_eq!(result.closed_count, 1);
        assert_eq!(result.ports[0].state, PortState::Open);
        assert_eq!(result.ports[0].timing_ns, 500_000);
        assert_eq!(result.ports[1].state, PortState::Closed);
        assert_eq!(result.ports[1].timing_ns, 200_000);
    }

    #[test]
    fn test_generic_collect_filtered_no_entry() {
        let bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(8080, 50003)];
        let result = collector.collect(&probes, &bpf, target_ip);

        assert_eq!(result.filtered_count, 1);
        assert_eq!(result.ports[0].state, PortState::Filtered);
    }

    #[test]
    fn test_generic_collect_cleanup() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 500_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(80, 50000), make_probe(443, 50001)];
        let _result = collector.collect(&probes, &bpf, target_ip);

        let deleted = bpf.deleted_entries();
        assert_eq!(deleted.len(), 2);
    }

    #[test]
    fn test_port_batching() {
        let ports: Vec<u16> = (1..=50).collect();
        let batch_size = 20;
        let batches: Vec<&[u16]> = ports.chunks(batch_size).collect();

        assert_eq!(batches.len(), 3); // 20 + 20 + 10
        assert_eq!(batches[0].len(), 20);
        assert_eq!(batches[1].len(), 20);
        assert_eq!(batches[2].len(), 10);
    }

    #[test]
    fn test_bpf_map_cleanup_partial() {
        // Mix of found and not-found entries; all should attempt cleanup
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 500_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );
        // Port 443 has no entry (filtered)

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(80, 50000), make_probe(443, 50001)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.open_count, 1);
        assert_eq!(result.filtered_count, 1);

        let deleted = bpf.deleted_entries();
        assert_eq!(
            deleted.len(),
            2,
            "cleanup attempted for all probes, even missing entries"
        );
    }

    // ===========================================
    // Firewalled reclassification tests (TDD)
    // ===========================================

    /// RST TTL significantly higher than open-port baseline → Firewalled.
    /// Open port has TTL=64; RST arrives with TTL=128 (>64+5) → firewall.
    #[test]
    fn test_firewalled_by_ttl_with_open_baseline() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        // Open port establishes baseline TTL=64
        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 5_000_000, // 5ms
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );
        // Closed port with RST TTL=128 — much higher than baseline 64 → Firewalled
        bpf.add_entry_v2(
            target_ip,
            22,
            50001,
            TimingMapEntry {
                delta_ns: 4_000_000,
                port_state: PortState::Closed,
                response_ttl: 128, // 128 > 64 + 5 → firewalled
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(80, 50000), make_probe(22, 50001)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.ports[1].state, PortState::Firewalled);
        assert_eq!(result.firewalled_count, 1);
        assert_eq!(result.closed_count, 0);
    }

    /// RST arrives in 50µs vs 5ms open RTT (< 20% of baseline) → Firewalled.
    #[test]
    fn test_firewalled_by_timing_with_open_baseline() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 5_000_000, // 5ms baseline
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );
        // RST in 50µs — well under 20% of 5ms AND under 500µs absolute threshold
        bpf.add_entry_v2(
            target_ip,
            9999,
            50001,
            TimingMapEntry {
                delta_ns: 50_000, // 50µs — 1% of 5ms baseline
                port_state: PortState::Closed,
                response_ttl: 64, // same TTL, no TTL signal
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(80, 50000), make_probe(9999, 50001)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.ports[1].state, PortState::Firewalled);
        assert_eq!(result.firewalled_count, 1);
    }

    /// RST TTL same as open-port baseline → stays Closed (no signal).
    #[test]
    fn test_not_firewalled_matching_ttl() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 5_000_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );
        // RST TTL=64 same as open, timing=4ms (80% of baseline) → Closed
        bpf.add_entry_v2(
            target_ip,
            22,
            50001,
            TimingMapEntry {
                delta_ns: 4_000_000, // 4ms — 80% of baseline, above 20% threshold
                port_state: PortState::Closed,
                response_ttl: 64, // same as open baseline
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(80, 50000), make_probe(22, 50001)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.ports[1].state, PortState::Closed);
        assert_eq!(result.firewalled_count, 0);
        assert_eq!(result.closed_count, 1);
    }

    /// No open ports available; RST arrives in 200µs → absolute threshold fires → Firewalled.
    #[test]
    fn test_firewalled_absolute_threshold_no_open_ports() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        // Only closed ports, no open baseline
        bpf.add_entry_v2(
            target_ip,
            22,
            50001,
            TimingMapEntry {
                delta_ns: 200_000, // 200µs — under 500µs absolute threshold
                port_state: PortState::Closed,
                response_ttl: 64,
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(22, 50001)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.ports[0].state, PortState::Firewalled);
        assert_eq!(result.firewalled_count, 1);
    }

    /// No open ports; RST arrives in 2ms → above absolute threshold → stays Closed.
    #[test]
    fn test_not_firewalled_slow_rst_no_open_ports() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            22,
            50001,
            TimingMapEntry {
                delta_ns: 2_000_000, // 2ms — above 500µs absolute threshold
                port_state: PortState::Closed,
                response_ttl: 64,
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![make_probe(22, 50001)];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.ports[0].state, PortState::Closed);
        assert_eq!(result.firewalled_count, 0);
        assert_eq!(result.closed_count, 1);
    }

    /// Batch with 1 open, 1 genuine-closed, 1 firewalled — counts all correct.
    #[test]
    fn test_firewalled_count_updated() {
        let mut bpf = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let target_ip: u32 = 0x0A000001;

        bpf.add_entry_v2(
            target_ip,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 5_000_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );
        // Genuine closed — same TTL, slow RST
        bpf.add_entry_v2(
            target_ip,
            22,
            50001,
            TimingMapEntry {
                delta_ns: 4_000_000,
                port_state: PortState::Closed,
                response_ttl: 64,
                response_win: 0,
            },
        );
        // Firewalled — TTL spike
        bpf.add_entry_v2(
            target_ip,
            8080,
            50002,
            TimingMapEntry {
                delta_ns: 4_500_000,
                port_state: PortState::Closed,
                response_ttl: 128,
                response_win: 0,
            },
        );

        let collector = DiscoveryCollector::new(Duration::from_secs(5));
        let probes = vec![
            make_probe(80, 50000),
            make_probe(22, 50001),
            make_probe(8080, 50002),
        ];
        let result = collector.collect_from_mock(&probes, &bpf, target_ip);

        assert_eq!(result.open_count, 1);
        assert_eq!(result.closed_count, 1);
        assert_eq!(result.firewalled_count, 1);
        assert_eq!(result.filtered_count, 0);
    }
}
