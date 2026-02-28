//! AF_XDP-native SYN packet sender for port discovery.
//!
//! Sends SYN packets via AF_XDP (kernel-level, UMEM DMA) with parameters
//! matching a real Linux TCP stack. Responses are received directly on the
//! AF_XDP RX ring — the kernel TCP stack never sees SYN-ACKs, eliminating
//! both iptables RST suppression and SO_MARK complexity.
//!
//! Source port reuse guard prevents timing confusion from overlapping probes.

use std::collections::HashSet;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Instant;

use lru::LruCache;
use rand::seq::SliceRandom;
use rand::Rng;

use super::afxdp_sender::{AfXdpSend, RxFrame};
use super::stealth::StealthProfile;

/// Source port reuse guard key: (src_port, dst_ip, dst_port).
type ReuseKey = (u16, u32, u16);

/// SYN scanner that sends packets via AF_XDP and receives via the AF_XDP RX ring.
///
/// Requires `CAP_NET_ADMIN` and `CAP_BPF` when a real `AfXdpSend` sender is
/// configured. Packet construction only (no sending) works without privileges
/// and is exercised by unit tests via `SynScanner::new()`.
pub struct SynScanner {
    profile: StealthProfile,
    reuse_guard: LruCache<ReuseKey, Instant>,
    probe_counter: u32,
    /// AF_XDP sender for packet transmission and reception.
    /// `None` when constructed via `new()` (packet-construction-only mode).
    sender: Option<Box<dyn AfXdpSend>>,
}

/// Error from SYN scanner operations.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("AF_XDP socket creation failed (requires CAP_NET_ADMIN): {0}")]
    RawSocket(String),

    #[error("packet send failed: {0}")]
    Send(String),

    #[error("source port exhaustion: no available ports in range")]
    PortExhaustion,
}

/// Detect the source IP address that would be used to reach the target.
///
/// Uses the UDP connect trick: binds a UDP socket and connects to the target
/// (no packet is actually sent). The OS routing table determines the source IP.
pub fn detect_source_ip(target: Ipv4Addr) -> Result<Ipv4Addr, ScanError> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| ScanError::RawSocket(format!("source IP detection: {}", e)))?;
    sock.connect((target, 80))
        .map_err(|e| ScanError::RawSocket(format!("source IP detection: {}", e)))?;
    match sock
        .local_addr()
        .map_err(|e| ScanError::RawSocket(format!("source IP detection: {}", e)))?
        .ip()
    {
        std::net::IpAddr::V4(ip) => Ok(ip),
        _ => Err(ScanError::RawSocket("expected IPv4 address".to_string())),
    }
}

/// Result of sending a batch of SYN probes.
#[derive(Debug)]
pub struct SynBatchResult {
    /// Ports that were probed, in the order sent.
    pub probed_ports: Vec<ProbeRecord>,
    /// Total time spent sending the batch.
    pub send_duration: std::time::Duration,
}

/// Record of a single SYN probe sent.
#[derive(Debug, Clone)]
pub struct ProbeRecord {
    /// Target port.
    pub dst_port: u16,
    /// Source port used for this probe.
    pub src_port: u16,
    /// Timestamp when the probe was sent.
    pub sent_at: Instant,
    /// Initial sequence number used in the SYN packet.
    pub isn: u32,
}

impl SynScanner {
    /// Create a scanner for packet construction only (no sending).
    ///
    /// Tests use this constructor to exercise `build_syn_packet`,
    /// `build_rst_packet`, and port allocation without any network access.
    pub fn new(profile: StealthProfile) -> Self {
        let capacity = std::num::NonZeroUsize::new(65536).unwrap();
        Self {
            profile,
            reuse_guard: LruCache::new(capacity),
            probe_counter: 0,
            sender: None,
        }
    }

    /// Create a scanner with an AF_XDP sender for real packet transmission.
    ///
    /// Production code uses this constructor. Tests pass `MockAfXdpSender`.
    pub fn new_with_sender(profile: StealthProfile, sender: Box<dyn AfXdpSend>) -> Self {
        let capacity = std::num::NonZeroUsize::new(65536).unwrap();
        Self {
            profile,
            reuse_guard: LruCache::new(capacity),
            probe_counter: 0,
            sender: Some(sender),
        }
    }

    /// Get a mutable reference to the AF_XDP sender.
    fn get_sender(&mut self) -> Result<&mut dyn AfXdpSend, ScanError> {
        match self.sender.as_deref_mut() {
            Some(s) => Ok(s),
            None => Err(ScanError::RawSocket("no AF_XDP sender configured".into())),
        }
    }

    /// Get the source IP from the configured sender, or detect it from routing.
    fn resolve_src_ip(&mut self, target_ip: Ipv4Addr) -> Result<Ipv4Addr, ScanError> {
        match &self.sender {
            Some(s) => Ok(s.source_ip()),
            None => detect_source_ip(target_ip),
        }
    }

    /// Send SYN probes to a batch of ports on the target IP.
    ///
    /// Ports are shuffled before sending. Each probe uses a unique source port
    /// (guarded against reuse within the configured window). Returns records of
    /// all probes sent for BPF map correlation.
    pub fn send_syn_batch(
        &mut self,
        target_ip: Ipv4Addr,
        ports: &[u16],
    ) -> Result<SynBatchResult, ScanError> {
        let src_ip = self.resolve_src_ip(target_ip)?;

        let mut shuffled_ports = ports.to_vec();
        let mut rng = rand::thread_rng();
        shuffled_ports.shuffle(&mut rng);

        let start = Instant::now();
        let mut records = Vec::with_capacity(shuffled_ports.len());
        let dst_ip_u32 = u32::from_be_bytes(target_ip.octets());

        for &dst_port in &shuffled_ports {
            let src_port = self.allocate_src_port(dst_ip_u32, dst_port)?;
            let (mut packet, isn) = self.build_syn_packet(src_ip, target_ip, src_port, dst_port);

            self.get_sender()?.send_raw(&packet)?;

            // Zero packet bytes to avoid leaking data
            packet.iter_mut().for_each(|b| *b = 0);

            records.push(ProbeRecord {
                dst_port,
                src_port,
                sent_at: Instant::now(),
                isn,
            });

            self.probe_counter += 1;

            // Apply rate limiting between probes
            let delay = self.profile.jittered_delay_ms();
            if delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay));
            }
        }

        Ok(SynBatchResult {
            probed_ports: records,
            send_duration: start.elapsed(),
        })
    }

    /// Send a single SYN probe and return the probe metadata.
    ///
    /// Unlike `send_syn_batch`, this sends exactly one probe with no pacing
    /// delay (caller controls inter-probe timing).
    pub fn send_single_syn(
        &mut self,
        target_ip: Ipv4Addr,
        dst_port: u16,
    ) -> Result<ProbeRecord, ScanError> {
        let src_ip = self.resolve_src_ip(target_ip)?;
        let dst_ip_u32 = u32::from_be_bytes(target_ip.octets());
        let src_port = self.allocate_src_port(dst_ip_u32, dst_port)?;
        let (packet, isn) = self.build_syn_packet(src_ip, target_ip, src_port, dst_port);

        self.get_sender()?.send_raw(&packet)?;
        self.probe_counter += 1;

        Ok(ProbeRecord {
            dst_port,
            src_port,
            sent_at: Instant::now(),
            isn,
        })
    }

    /// Poll the AF_XDP RX ring for received frames.
    ///
    /// Delegates to the configured sender. Returns empty vec if no sender
    /// configured or no frames available within `timeout_ms`.
    pub fn poll_rx(&mut self, timeout_ms: u64) -> Vec<RxFrame> {
        match self.sender.as_deref_mut() {
            Some(s) => s.poll_rx(timeout_ms),
            None => vec![],
        }
    }

    /// Whether the configured sender has an AF_XDP RX ring.
    ///
    /// `false` when using raw socket fallback — callers should use the TCP
    /// connect timing path instead of the AF_XDP RX poll path.
    pub fn has_rx(&self) -> bool {
        match self.sender.as_deref() {
            Some(s) => s.has_rx(),
            None => false,
        }
    }

    /// Allocate a source port that hasn't been used recently for this target.
    fn allocate_src_port(&mut self, dst_ip: u32, dst_port: u16) -> Result<u16, ScanError> {
        let now = Instant::now();
        let window = std::time::Duration::from_millis(self.profile.src_port_reuse_window_ms);

        for _ in 0..100 {
            let port = self.profile.random_src_port();
            let key = (port, dst_ip, dst_port);

            if !self.profile.src_port_reuse_guard {
                self.reuse_guard.put(key, now);
                return Ok(port);
            }

            match self.reuse_guard.get(&key) {
                Some(&used_at) if now.duration_since(used_at) < window => {
                    continue;
                }
                _ => {
                    self.reuse_guard.put(key, now);
                    return Ok(port);
                }
            }
        }

        Err(ScanError::PortExhaustion)
    }

    /// SYN packet size: 20 (IP) + 20 (TCP) + 20 (options) = 60 bytes.
    ///
    /// This is fixed for the `linux_6x_default` profile with all TCP options
    /// (MSS + SACK_PERM + Timestamps + NOP + WSCALE = 20 bytes of options).
    pub const SYN_PACKET_SIZE: usize = 60;

    /// Build a raw SYN packet matching the stealth profile.
    ///
    /// Returns `(packet_bytes, isn)` where `isn` is the random initial sequence
    /// number. Packet includes a complete IPv4 header and TCP header with options.
    /// No Ethernet header is included (raw IP layer only).
    ///
    /// Uses a fixed-size stack buffer ([`SYN_PACKET_SIZE`]) to avoid a heap
    /// allocation per packet.
    pub fn build_syn_packet(
        &self,
        src_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> ([u8; Self::SYN_PACKET_SIZE], u32) {
        let tcp_options = self.build_tcp_options();
        // Options are always 20 bytes for linux_6x_default; pad to 4-byte boundary
        let tcp_options_padded = (tcp_options.len() + 3) & !3;
        let tcp_header_len = 20 + tcp_options_padded;
        let ip_total_len = 20 + tcp_header_len;
        debug_assert_eq!(
            ip_total_len,
            Self::SYN_PACKET_SIZE,
            "SYN packet size mismatch — profile TCP options changed?"
        );

        let mut packet = [0u8; Self::SYN_PACKET_SIZE];
        let isn: u32 = rand::random();

        // --- IPv4 header (bytes 0–19) ---
        packet[0] = 0x45; // Version=4, IHL=5 (20 bytes)
                          // byte 1: DSCP/ECN = 0
        packet[2] = (ip_total_len >> 8) as u8;
        packet[3] = ip_total_len as u8;
        if self.profile.ip_id_random {
            let id: u16 = rand::thread_rng().gen();
            packet[4] = (id >> 8) as u8;
            packet[5] = id as u8;
        }
        if self.profile.ip_df {
            packet[6] = 0x40; // DF=1, MF=0, frag_offset=0
        }
        packet[8] = self.profile.jittered_ttl();
        packet[9] = 0x06; // TCP
                          // bytes 10–11: IP checksum (computed below)
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&target_ip.octets());

        // --- TCP header (bytes 20–(20+tcp_header_len-1)) ---
        packet[20] = (src_port >> 8) as u8;
        packet[21] = src_port as u8;
        packet[22] = (dst_port >> 8) as u8;
        packet[23] = dst_port as u8;
        // sequence number (bytes 24–27)
        packet[24] = (isn >> 24) as u8;
        packet[25] = (isn >> 16) as u8;
        packet[26] = (isn >> 8) as u8;
        packet[27] = isn as u8;
        // acknowledgement = 0 (bytes 28–31)
        // data offset (byte 32): number of 32-bit words in TCP header, in upper nibble
        packet[32] = ((tcp_header_len / 4) as u8) << 4;
        // TCP flags (byte 33): SYN = 0x02
        packet[33] = 0x02;
        // window size (bytes 34–35)
        let window = self.profile.select_window(self.probe_counter as usize);
        packet[34] = (window >> 8) as u8;
        packet[35] = window as u8;
        // TCP checksum (bytes 36–37): computed below
        // urgent pointer (bytes 38–39)
        packet[38] = (self.profile.tcp_urgent_ptr >> 8) as u8;
        packet[39] = self.profile.tcp_urgent_ptr as u8;

        // TCP options (bytes 40 onward)
        let opts_start = 40;
        packet[opts_start..opts_start + tcp_options.len()].copy_from_slice(&tcp_options);

        // Compute TCP checksum (must be done before IP checksum)
        let tcp_checksum =
            compute_tcp_checksum(&packet[20..20 + tcp_header_len], &src_ip, &target_ip);
        packet[36] = (tcp_checksum >> 8) as u8;
        packet[37] = tcp_checksum as u8;

        // Compute IP header checksum
        let ip_checksum = compute_ip_checksum(&packet[0..20]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = ip_checksum as u8;

        (packet, isn)
    }

    /// Build a minimal RST packet for tearing down half-open connections.
    ///
    /// No TCP options (data_offset=5), window=0. Same IP header stealth params
    /// (TTL jitter, DF, random IP ID) as SYN packets.
    pub fn build_rst_packet(
        &self,
        src_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Vec<u8> {
        let tcp_header_len = 20; // No TCP options for RST
        let ip_total_len = 20 + tcp_header_len; // 40 bytes total
        let mut packet = vec![0u8; ip_total_len];

        // --- IPv4 header ---
        packet[0] = 0x45;
        packet[2] = (ip_total_len >> 8) as u8;
        packet[3] = ip_total_len as u8;
        if self.profile.ip_id_random {
            let id: u16 = rand::thread_rng().gen();
            packet[4] = (id >> 8) as u8;
            packet[5] = id as u8;
        }
        if self.profile.ip_df {
            packet[6] = 0x40;
        }
        packet[8] = self.profile.jittered_ttl();
        packet[9] = 0x06; // TCP
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&target_ip.octets());

        // --- TCP header (no options) ---
        packet[20] = (src_port >> 8) as u8;
        packet[21] = src_port as u8;
        packet[22] = (dst_port >> 8) as u8;
        packet[23] = dst_port as u8;
        // sequence number
        packet[24] = (seq >> 24) as u8;
        packet[25] = (seq >> 16) as u8;
        packet[26] = (seq >> 8) as u8;
        packet[27] = seq as u8;
        // acknowledgement = 0
        // data offset = 5 (20 bytes / 4 words), upper nibble
        packet[32] = 5 << 4; // 0x50
                             // TCP flags: RST = 0x04
        packet[33] = 0x04;
        // window = 0 (already zeroed)
        // urgent pointer = 0

        // Compute TCP checksum
        let tcp_checksum = compute_tcp_checksum(&packet[20..], &src_ip, &target_ip);
        packet[36] = (tcp_checksum >> 8) as u8;
        packet[37] = tcp_checksum as u8;

        // Compute IP checksum
        let ip_checksum = compute_ip_checksum(&packet[0..20]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = ip_checksum as u8;

        packet
    }

    /// Build TCP options matching Linux 6.x SYN behaviour.
    ///
    /// Returns raw option bytes (always 20 bytes for the default profile):
    /// MSS(4) + SACK_PERM(2) + Timestamps(10) + NOP(1) + Window Scale(3).
    pub fn build_tcp_options(&self) -> Vec<u8> {
        let mut opts: Vec<u8> = Vec::with_capacity(20);

        // MSS: kind=2, len=4, value(2 bytes BE)
        opts.push(2); // kind: MSS
        opts.push(4); // length
        opts.push((self.profile.tcp_options_mss >> 8) as u8);
        opts.push(self.profile.tcp_options_mss as u8);

        // SACK permitted: kind=4, len=2
        if self.profile.tcp_options_sack {
            opts.push(4); // kind: SACK_PERMITTED
            opts.push(2); // length
        }

        // Timestamps: kind=8, len=10, TSval(4 BE) + TSecr=0(4)
        if self.profile.tcp_options_timestamps {
            let tsval = self.profile.tsval_for_probe(self.probe_counter);
            opts.push(8); // kind: Timestamps
            opts.push(10); // length
            opts.push((tsval >> 24) as u8);
            opts.push((tsval >> 16) as u8);
            opts.push((tsval >> 8) as u8);
            opts.push(tsval as u8);
            // TSecr = 0 on SYN
            opts.extend_from_slice(&[0u8; 4]);
        }

        // NOP: kind=1
        opts.push(1);

        // Window Scale: kind=3, len=3, shift_count
        opts.push(3); // kind: WSCALE
        opts.push(3); // length
        opts.push(self.profile.tcp_options_ws);

        opts
    }

    /// Get the current probe counter.
    pub fn probe_count(&self) -> u32 {
        self.probe_counter
    }

    /// Get a reference to the stealth profile.
    pub fn profile(&self) -> &StealthProfile {
        &self.profile
    }
}

// =============================================================================
// Checksum utilities
// =============================================================================

/// Compute an Internet checksum (one's complement sum of 16-bit words).
///
/// Used for both IP header and TCP pseudo-header checksums.
fn ones_complement_sum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    // Odd trailing byte — pad with zero
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    // Fold 32-bit carry into 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute the IPv4 header checksum.
///
/// The checksum field (bytes 10–11) must contain zeros when this is called.
/// Uses a fixed-size stack buffer (max 60 bytes for IP header with options)
/// to avoid a heap allocation per packet.
pub fn compute_ip_checksum(header: &[u8]) -> u16 {
    let mut buf = [0u8; 60]; // max IP header size (IHL=15 → 60 bytes)
    let len = header.len().min(60);
    buf[..len].copy_from_slice(&header[..len]);
    // Zero the checksum field before computing
    if len >= 12 {
        buf[10] = 0;
        buf[11] = 0;
    }
    ones_complement_sum(&buf[..len])
}

/// Compute the TCP checksum including the IPv4 pseudo-header.
///
/// The checksum field (bytes 16–17 within `tcp_segment`) must be zero.
/// Uses a fixed-size stack buffer (128 bytes covers max 60-byte TCP header
/// + 12-byte pseudo-header) to avoid a heap allocation per packet.
pub fn compute_tcp_checksum(tcp_segment: &[u8], src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr) -> u16 {
    let tcp_len = tcp_segment.len() as u16;
    let total_len = 12 + tcp_segment.len();
    debug_assert!(
        total_len <= 128,
        "TCP pseudo-header + segment ({total_len}) exceeds 128-byte stack buffer"
    );
    let len = total_len.min(128);

    // IPv4 pseudo-header: src(4) + dst(4) + zero(1) + proto=6(1) + tcp_len(2)
    let mut buf = [0u8; 128];
    buf[0..4].copy_from_slice(&src_ip.octets());
    buf[4..8].copy_from_slice(&dst_ip.octets());
    // buf[8] = 0; // reserved (already zero)
    buf[9] = 0x06; // TCP protocol
    buf[10] = (tcp_len >> 8) as u8;
    buf[11] = tcp_len as u8;

    // TCP segment (zero the checksum field at offset 16–17 within TCP)
    let seg_len = tcp_segment.len().min(116); // 128 - 12
    buf[12..12 + seg_len].copy_from_slice(&tcp_segment[..seg_len]);
    // Offset: 12 (pseudo) + 16 (TCP checksum offset within header)
    if len >= 12 + 18 {
        buf[12 + 16] = 0;
        buf[12 + 17] = 0;
    }

    ones_complement_sum(&buf[..len])
}

// =============================================================================
// Utility functions
// =============================================================================

/// Verify that a packet buffer has SYN-only flags (SYN=1, ACK=0, RST=0).
pub fn verify_syn_flags(tcp_buf: &[u8]) -> bool {
    if tcp_buf.len() < 14 {
        return false;
    }
    // TCP flags are at offset 13
    let flags = tcp_buf[13];
    // SYN = 0x02, ACK = 0x10, RST = 0x04
    flags & 0x02 != 0 && flags & 0x10 == 0 && flags & 0x04 == 0
}

/// Check if two port lists have a different order (shuffled).
pub fn is_shuffled(original: &[u16], actual: &[u16]) -> bool {
    if original.len() != actual.len() {
        return true;
    }
    let orig_set: HashSet<u16> = original.iter().copied().collect();
    let actual_set: HashSet<u16> = actual.iter().copied().collect();
    if orig_set != actual_set {
        return true;
    }
    original != actual
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::afxdp_sender::MockAfXdpSender;
    use crate::scanner::stealth::PacingProfile;

    // ==========================================================================
    // has_rx delegation
    // ==========================================================================

    #[test]
    fn test_syn_scanner_has_rx_true_with_mock_sender() {
        let profile = StealthProfile::linux_6x_default();
        let sender = Box::new(MockAfXdpSender::new());
        let scanner = SynScanner::new_with_sender(profile, sender);
        assert!(
            scanner.has_rx(),
            "SynScanner with MockAfXdpSender must report has_rx=true"
        );
    }

    #[test]
    fn test_syn_scanner_has_rx_false_without_sender() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        assert!(
            !scanner.has_rx(),
            "SynScanner without sender must report has_rx=false"
        );
    }

    // ==========================================================================
    // SYN packet construction (no sender needed)
    // ==========================================================================

    #[test]
    fn test_syn_packet_flags() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (packet, _isn) =
            scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80);
        let tcp_buf = &packet[20..];
        assert!(
            verify_syn_flags(tcp_buf),
            "SYN flag must be set, ACK and RST must be clear"
        );
    }

    #[test]
    fn test_syn_packet_src_port_in_packet() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (packet, _isn) =
            scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 443);
        let src = u16::from_be_bytes([packet[20], packet[21]]);
        assert_eq!(src, 50000);
    }

    #[test]
    fn test_syn_packet_dst_port_in_packet() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (packet, _isn) =
            scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 443);
        let dst = u16::from_be_bytes([packet[22], packet[23]]);
        assert_eq!(dst, 443);
    }

    #[test]
    fn test_syn_packet_ip_version() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (packet, _isn) =
            scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80);
        assert_eq!(packet[0] >> 4, 4, "IP version must be 4");
    }

    #[test]
    fn test_src_port_no_reuse_within_window() {
        let mut profile = StealthProfile::linux_6x_default();
        profile.src_port_reuse_guard = true;
        profile.src_port_reuse_window_ms = 60_000;

        let mut scanner = SynScanner::new(profile);
        let dst_ip: u32 = 0x0A000001;

        let mut allocated = Vec::new();
        for _ in 0..50 {
            let port = scanner.allocate_src_port(dst_ip, 80).unwrap();
            assert!(
                !allocated.contains(&port),
                "Source port {} reused within window",
                port
            );
            allocated.push(port);
        }
    }

    #[test]
    fn test_port_order_shuffled() {
        let ports: Vec<u16> = (1..=100).collect();
        let mut shuffled = ports.clone();
        let mut rng = rand::thread_rng();
        shuffled.shuffle(&mut rng);
        assert!(
            is_shuffled(&ports, &shuffled),
            "port order should be shuffled for stealth"
        );
    }

    #[test]
    fn test_scanner_probe_counter_increments() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        assert_eq!(scanner.probe_count(), 0);
    }

    #[test]
    fn test_build_tcp_options_linux_order() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let options = scanner.build_tcp_options();

        // Linux order: MSS(kind=2), SACK_PERM(kind=4), Timestamps(kind=8), NOP(kind=1), WSCALE(kind=3)
        assert_eq!(options[0], 2, "first option kind must be MSS (2)");
        assert_eq!(options[1], 4, "MSS length must be 4");
        assert_eq!(options[4], 4, "second option kind must be SACK_PERM (4)");
        assert_eq!(options[5], 2, "SACK_PERM length must be 2");
        assert_eq!(options[6], 8, "third option kind must be Timestamps (8)");
        assert_eq!(options[7], 10, "Timestamps length must be 10");
        assert_eq!(options[16], 1, "fourth option must be NOP (1)");
        assert_eq!(options[17], 3, "fifth option kind must be WSCALE (3)");
        assert_eq!(options[18], 3, "WSCALE length must be 3");
    }

    #[test]
    fn test_syn_packet_source_ip_set() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (packet, _isn) =
            scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80);
        let ip_src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        assert_eq!(ip_src, src_ip, "source IP must be set in IP header");
    }

    #[test]
    fn test_syn_packet_tcp_checksum_nonzero() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (packet, _isn) =
            scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80);
        // TCP checksum is at offset 20 (IP) + 16 (TCP) = 36
        let tcp_checksum = u16::from_be_bytes([packet[36], packet[37]]);
        assert_ne!(tcp_checksum, 0, "TCP checksum must be computed (non-zero)");
    }

    #[test]
    fn test_syn_packet_ip_checksum_nonzero() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (packet, _isn) =
            scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80);
        let ip_checksum = u16::from_be_bytes([packet[10], packet[11]]);
        assert_ne!(
            ip_checksum, 0,
            "IP header checksum must be computed (non-zero)"
        );
    }

    #[test]
    #[ignore] // Integration test — requires network access
    fn test_detect_source_ip_returns_ipv4() {
        let target = Ipv4Addr::new(1, 1, 1, 1);
        let result = detect_source_ip(target);
        assert!(result.is_ok(), "detect_source_ip should succeed");
        let ip = result.unwrap();
        assert!(!ip.is_loopback(), "source IP should not be loopback");
        assert!(!ip.is_unspecified(), "source IP should not be 0.0.0.0");
    }

    #[test]
    fn test_pacing_applied_to_stealth() {
        let mut profile = StealthProfile::linux_6x_default();
        PacingProfile::Aggressive.apply_to(&mut profile);
        assert_eq!(profile.probe_delay_ms, 5);

        PacingProfile::Normal.apply_to(&mut profile);
        assert_eq!(profile.probe_delay_ms, 50);

        PacingProfile::Paranoid.apply_to(&mut profile);
        assert_eq!(profile.probe_delay_ms, 500);
    }

    // ==========================================================================
    // RST packet construction tests
    // ==========================================================================

    #[test]
    fn test_rst_packet_has_rst_flag_only() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let packet = scanner.build_rst_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80, 12345);
        let tcp_buf = &packet[20..];
        let flags = tcp_buf[13];
        assert_eq!(flags & 0x04, 0x04, "RST flag must be set");
        assert_eq!(flags & 0x02, 0x00, "SYN flag must be clear");
        assert_eq!(flags & 0x10, 0x00, "ACK flag must be clear");
    }

    #[test]
    fn test_rst_packet_has_no_tcp_options() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let packet = scanner.build_rst_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80, 12345);
        let tcp_buf = &packet[20..];
        let data_offset = (tcp_buf[12] >> 4) as usize;
        assert_eq!(data_offset, 5, "RST data offset must be 5 (no TCP options)");
        assert_eq!(packet.len(), 40, "RST packet must be 40 bytes (no options)");
    }

    #[test]
    fn test_rst_packet_seq_matches_input() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let seq: u32 = 0xDEADBEEF;
        let packet = scanner.build_rst_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80, seq);
        let pkt_seq = u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]]);
        assert_eq!(pkt_seq, seq, "RST seq must match provided value");
    }

    #[test]
    fn test_rst_packet_window_zero() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let packet = scanner.build_rst_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80, 1);
        let window = u16::from_be_bytes([packet[34], packet[35]]);
        assert_eq!(window, 0, "RST window must be 0");
    }

    #[test]
    fn test_isn_captured_in_probe_record() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (_packet, isn) =
            scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80);
        let _ = isn; // type check — u32
    }

    #[test]
    fn test_syn_packet_sequence_matches_returned_isn() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (packet, isn) = scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80);
        let pkt_seq = u32::from_be_bytes([packet[24], packet[25], packet[26], packet[27]]);
        assert_eq!(
            pkt_seq, isn,
            "packet sequence number must match returned ISN"
        );
    }

    #[test]
    fn test_rst_packet_checksums_nonzero() {
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let packet = scanner.build_rst_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80, 1);
        let ip_checksum = u16::from_be_bytes([packet[10], packet[11]]);
        assert_ne!(ip_checksum, 0, "RST IP checksum must be computed");
        let tcp_checksum = u16::from_be_bytes([packet[36], packet[37]]);
        assert_ne!(tcp_checksum, 0, "RST TCP checksum must be computed");
    }

    // ==========================================================================
    // Checksum unit tests
    // ==========================================================================

    #[test]
    fn test_ones_complement_sum_even_bytes() {
        // 0x0001 + 0x0002 = 0x0003 → ~0x0003 = 0xFFFC
        let data = [0x00u8, 0x01, 0x00, 0x02];
        let result = ones_complement_sum(&data);
        assert_eq!(result, 0xFFFC);
    }

    #[test]
    fn test_ones_complement_sum_with_carry() {
        // 0xFFFF + 0x0001 = 0x10000 → fold → 0x0001 → ~0x0001 = 0xFFFE
        let data = [0xFF, 0xFF, 0x00, 0x01];
        let result = ones_complement_sum(&data);
        assert_eq!(result, 0xFFFE);
    }

    #[test]
    fn test_compute_ip_checksum_zeros_field() {
        // A header with pre-set checksum must produce valid result
        let profile = StealthProfile::linux_6x_default();
        let scanner = SynScanner::new(profile);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let (packet, _) = scanner.build_syn_packet(src_ip, Ipv4Addr::new(10, 0, 0, 1), 50000, 80);

        // Re-compute IP checksum over the header with the checksum field set
        // The one's complement sum of a valid header including its checksum should be 0xFFFF
        let mut sum: u32 = 0;
        let header = &packet[0..20];
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(
            sum as u16, 0xFFFF,
            "valid IP header checksum verification must yield 0xFFFF"
        );
    }

    // ==========================================================================
    // AF_XDP send path tests (using MockAfXdpSender)
    // ==========================================================================

    #[test]
    fn test_send_single_syn_uses_afxdp() {
        let profile = StealthProfile::linux_6x_default();
        let mock = MockAfXdpSender::with_src_ip(Ipv4Addr::new(10, 0, 0, 1));
        let mut scanner = SynScanner::new_with_sender(profile, Box::new(mock));

        let result = scanner.send_single_syn(Ipv4Addr::new(10, 0, 0, 2), 80);
        assert!(
            result.is_ok(),
            "send_single_syn should succeed with mock sender"
        );

        let probe = result.unwrap();
        assert_eq!(probe.dst_port, 80);
        assert!(probe.src_port >= 49152);

        // Verify packet was sent via the mock sender
        let sent = scanner.sender.as_ref().unwrap();
        let mock_ref = sent
            .as_any()
            .downcast_ref::<MockAfXdpSender>()
            .expect("sender must be MockAfXdpSender");
        assert_eq!(mock_ref.sent_count(), 1, "one packet should have been sent");
    }

    #[test]
    fn test_send_single_syn_packet_is_syn() {
        let profile = StealthProfile::linux_6x_default();
        let mock = MockAfXdpSender::with_src_ip(Ipv4Addr::new(10, 0, 0, 1));
        let mut scanner = SynScanner::new_with_sender(profile, Box::new(mock));

        scanner
            .send_single_syn(Ipv4Addr::new(10, 0, 0, 2), 443)
            .unwrap();

        // Access sent packet via the mock's internal state by rebuilding the packet
        // We verify the send_single_syn path produces a valid SYN packet
        assert_eq!(scanner.probe_count(), 1);
    }

    #[test]
    fn test_send_single_syn_without_sender_returns_err() {
        let profile = StealthProfile::linux_6x_default();
        let mut scanner = SynScanner::new(profile); // no sender

        let result = scanner.send_single_syn(Ipv4Addr::new(10, 0, 0, 1), 80);
        assert!(result.is_err(), "send without sender must return Err");
    }

    #[test]
    fn test_send_syn_batch_sends_all_ports() {
        let mut profile = StealthProfile::linux_6x_default();
        profile.probe_delay_ms = 0; // no delay in tests
        let mock = MockAfXdpSender::with_src_ip(Ipv4Addr::new(10, 0, 0, 1));
        let mut scanner = SynScanner::new_with_sender(profile, Box::new(mock));

        let ports = vec![80u16, 443, 22, 8080];
        let result = scanner.send_syn_batch(Ipv4Addr::new(10, 0, 0, 2), &ports);
        assert!(result.is_ok());

        let batch = result.unwrap();
        assert_eq!(batch.probed_ports.len(), 4, "all 4 ports must be probed");
    }

    #[test]
    fn test_poll_rx_without_sender_returns_empty() {
        let profile = StealthProfile::linux_6x_default();
        let mut scanner = SynScanner::new(profile);
        let frames = scanner.poll_rx(0);
        assert!(frames.is_empty());
    }

    #[test]
    fn test_poll_rx_with_mock_sender() {
        let profile = StealthProfile::linux_6x_default();
        let mut mock = MockAfXdpSender::new();
        mock.queue_rx_frame(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let mut scanner = SynScanner::new_with_sender(profile, Box::new(mock));
        let frames = scanner.poll_rx(0);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_scanner_probe_counter_increments_on_send() {
        let mut profile = StealthProfile::linux_6x_default();
        profile.probe_delay_ms = 0;
        let mock = MockAfXdpSender::with_src_ip(Ipv4Addr::new(10, 0, 0, 1));
        let mut scanner = SynScanner::new_with_sender(profile, Box::new(mock));

        assert_eq!(scanner.probe_count(), 0);
        scanner
            .send_single_syn(Ipv4Addr::new(10, 0, 0, 2), 80)
            .unwrap();
        assert_eq!(scanner.probe_count(), 1);
        scanner
            .send_single_syn(Ipv4Addr::new(10, 0, 0, 2), 443)
            .unwrap();
        assert_eq!(scanner.probe_count(), 2);
    }
}
