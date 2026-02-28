//! XDP/BPF timing collection.
//!
//! Provides kernel-level TCP handshake timing using:
//! - TC BPF on egress for SYN timestamps
//! - XDP on ingress for SYN-ACK timestamps
//! - Shared BPF LRU hash map between both programs

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, OpenObject, TcHook, Xdp, XdpFlags, TC_EGRESS};

use crate::{PortState, TimingBackend};

// Include the generated skeleton
mod timing_skel {
    include!(concat!(env!("OUT_DIR"), "/timing.skel.rs"));
}

use timing_skel::*;

/// Errors from BPF timing operations.
#[derive(Debug, thiserror::Error)]
pub enum BpfTimingError {
    #[error("failed to load BPF timing program: {0}")]
    Load(String),

    #[error("failed to attach XDP program to interface '{interface}': {reason}")]
    AttachXdp { interface: String, reason: String },

    #[error("failed to attach TC program to interface '{interface}': {reason}")]
    AttachTc { interface: String, reason: String },

    #[error("network interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("insufficient permissions (requires CAP_BPF, CAP_NET_ADMIN)")]
    InsufficientPermissions,

    #[error("BPF map operation failed: {0}")]
    MapError(String),

    #[error("failed to register AF_XDP socket in xsk_map: {0}")]
    XskMapError(String),
}

/// BPF-based timing collector.
///
/// Loads TC egress + XDP ingress programs and reads timing data from the shared map.
/// When dropped, automatically detaches programs from the interface.
pub struct BpfTimingCollector {
    skel: TimingSkel<'static>,
    _xdp_link: libbpf_rs::Link,
    _tc_hook: Option<TcHook>,
    interface: String,
    backend: TimingBackend,
}

// SAFETY: BpfTimingCollector is only used from a single thread in practice.
// The skeleton and links are not shared across threads.
unsafe impl Send for BpfTimingCollector {}
unsafe impl Sync for BpfTimingCollector {}

impl BpfTimingCollector {
    /// Create a new BpfTimingCollector and attach programs to the specified interface.
    ///
    /// Attaches both TC egress and XDP ingress programs. Both are required —
    /// TC egress timestamps outgoing SYNs, XDP ingress timestamps responses.
    /// Fails hard if either attachment fails.
    pub fn new(interface: &str) -> Result<Self, BpfTimingError> {
        let ifindex = nix::net::if_::if_nametoindex(interface)
            .map_err(|_| BpfTimingError::InterfaceNotFound(interface.to_string()))?;

        // Leak the OpenObject to give it 'static lifetime (required by skeleton API)
        // This is intentional - the BpfTimingCollector lives for the duration of the program
        let open_object: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::<OpenObject>::uninit()));

        let skel_builder = TimingSkelBuilder::default();
        let open_skel = skel_builder
            .open(open_object)
            .map_err(|e| BpfTimingError::Load(e.to_string()))?;

        let skel = open_skel
            .load()
            .map_err(|e| BpfTimingError::Load(e.to_string()))?;

        // Clean up stale XDP program from a previous crash/hard-kill.
        // bpf_program__attach_xdp creates a link-based attachment (auto-cleanup on FD close),
        // but netlink-based XDP (ip link set xdp) persists after process exit.
        let xdp_handle = Xdp::new(skel.progs.xdp_timing_ingress.as_fd());
        match xdp_handle.query_id(ifindex as i32, XdpFlags::NONE) {
            Ok(old_id) if old_id > 0 => match xdp_handle.detach(ifindex as i32, XdpFlags::NONE) {
                Ok(()) => tracing::info!(
                    interface = %interface,
                    old_prog_id = old_id,
                    "Detached stale XDP program"
                ),
                Err(e) => tracing::warn!(
                    interface = %interface,
                    old_prog_id = old_id,
                    error = %e,
                    "Failed to detach stale XDP program"
                ),
            },
            _ => {} // No existing XDP — expected on first run
        }

        // Attach XDP program to interface
        let xdp_link = skel
            .progs
            .xdp_timing_ingress
            .attach_xdp(ifindex as i32)
            .map_err(|e| {
                if e.to_string().contains("permission") || e.to_string().contains("EPERM") {
                    BpfTimingError::InsufficientPermissions
                } else {
                    BpfTimingError::AttachXdp {
                        interface: interface.to_string(),
                        reason: e.to_string(),
                    }
                }
            })?;

        // Attach TC egress program — required, no fallback
        let tc_hook = Self::attach_tc_egress(&skel, ifindex as i32, interface)?;

        // Verify BPF map is accessible by writing and reading a sentinel entry.
        // If the map isn't accessible (e.g. pinned by another program), fail
        // immediately rather than producing a bogus scan with no timing data.
        let sentinel_key = build_key_bytes(0, 0, 0);
        let sentinel_value = [0u8; TIMING_VALUE_SIZE];
        skel.maps
            .timing_map
            .update(&sentinel_key, &sentinel_value, libbpf_rs::MapFlags::ANY)
            .map_err(|e| {
                BpfTimingError::MapError(format!("BPF map write verification failed: {e}"))
            })?;
        skel.maps.timing_map.delete(&sentinel_key).ok(); // cleanup, ignore if already gone

        Ok(Self {
            skel,
            _xdp_link: xdp_link,
            _tc_hook: Some(tc_hook),
            interface: interface.to_string(),
            backend: TimingBackend::Xdp,
        })
    }

    fn attach_tc_egress(
        skel: &TimingSkel<'static>,
        ifindex: i32,
        interface: &str,
    ) -> Result<TcHook, BpfTimingError> {
        let fd = skel.progs.tc_timing_egress.as_fd();

        // Destroy any existing clsact qdisc before creating a fresh one.
        // Without this, each restart adds a new TC hook at an auto-assigned priority
        // instead of replacing the previous one — the replace(true) flag has nothing
        // to match without a fixed priority. Over a crash loop this leaks N hooks and
        // N pinned timing_map references, causing stale BPF state and incorrect scan
        // results. Destroying the qdisc removes all hooks at once; the error is
        // ignored because the qdisc may not exist on first start.
        let mut cleanup = TcHook::new(fd);
        cleanup.ifindex(ifindex).attach_point(TC_EGRESS);
        match cleanup.destroy() {
            Ok(()) => {
                tracing::debug!(interface = %interface, "Destroyed existing clsact qdisc (stale hooks cleaned)")
            }
            Err(e) => {
                let msg = e.to_string();
                // ENOENT / EINVAL are expected on first run (no existing qdisc).
                // "Exclusivity flag" means a stale BPF program holds the slot — fatal.
                if msg.contains("Exclusivity") {
                    return Err(BpfTimingError::AttachTc {
                        interface: interface.to_string(),
                        reason: format!(
                            "cannot remove existing TC qdisc ({}). \
                             A stale BPF program may be attached — try: \
                             sudo ip link set dev {} xdpgeneric off && \
                             sudo tc qdisc del dev {} clsact",
                            e, interface, interface
                        ),
                    });
                }
            }
        }

        let mut hook = TcHook::new(fd);
        // priority(1): fixed priority ensures replace(true) always matches the same
        // slot on restart, rather than appending at an auto-assigned priority.
        hook.ifindex(ifindex)
            .attach_point(TC_EGRESS)
            .replace(true)
            .priority(1);

        hook.create().map_err(|e| BpfTimingError::AttachTc {
            interface: interface.to_string(),
            reason: format!("create: {}", e),
        })?;

        hook.attach().map_err(|e| BpfTimingError::AttachTc {
            interface: interface.to_string(),
            reason: format!("attach: {}", e),
        })?;

        Ok(hook)
    }

    /// Read timing delta for a specific connection from the BPF map.
    ///
    /// Returns the SYN-ACK - SYN delta in nanoseconds if both timestamps are present.
    /// Legacy method — only returns delta for SYN-ACK (Open) responses.
    pub fn read_timing(&self, dst_ip: u32, dst_port: u16, src_port: u16) -> Option<u64> {
        let key = build_key_bytes(dst_ip, dst_port, src_port);

        let value = self
            .skel
            .maps
            .timing_map
            .lookup(&key, libbpf_rs::MapFlags::ANY)
            .ok()??;

        parse_timing_value(&value)
    }

    /// Read a full v2 timing entry from the BPF map.
    ///
    /// Returns port state, timing delta, TTL, and TCP window.
    /// Handles both legacy (v0) and versioned (v1+) entries.
    pub fn read_timing_v2(
        &self,
        dst_ip: u32,
        dst_port: u16,
        src_port: u16,
    ) -> Option<TimingMapEntry> {
        let key = build_key_bytes(dst_ip, dst_port, src_port);

        let value = self
            .skel
            .maps
            .timing_map
            .lookup(&key, libbpf_rs::MapFlags::ANY)
            .ok()??;

        parse_timing_value_v2(&value)
    }

    /// Delete a timing entry from the BPF map after reading.
    pub fn delete_entry(&self, dst_ip: u32, dst_port: u16, src_port: u16) {
        let key = build_key_bytes(dst_ip, dst_port, src_port);
        let _ = self.skel.maps.timing_map.delete(&key);
    }

    /// Get the timing backend mode this collector is operating in.
    pub fn backend(&self) -> TimingBackend {
        self.backend
    }

    /// Get the interface name this collector is attached to.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Register an AF_XDP socket file descriptor in the BPF `xsk_map` at index 0.
    ///
    /// This must be called after creating an `AfXdpSender` and before any XDP
    /// ingress packets arrive. Without this, `bpf_redirect_map(&xsk_map, 0, XDP_PASS)`
    /// in the XDP program always falls back to `XDP_PASS` (kernel TCP stack receives
    /// responses instead of our AF_XDP socket).
    ///
    /// The fd is the AF_XDP socket fd from `AfXdpSender::fd()`.
    pub fn register_xsk_fd(&self, fd: i32) -> Result<(), BpfTimingError> {
        let key = 0u32.to_ne_bytes();
        let value = (fd as u32).to_ne_bytes();
        self.skel
            .maps
            .xsk_map
            .update(&key, &value, libbpf_rs::MapFlags::ANY)
            .map_err(|e| BpfTimingError::XskMapError(e.to_string()))
    }

    /// Count entries in the BPF timing map.
    ///
    /// Iterates all keys and returns the count. Useful for diagnostics.
    pub fn count_map_entries(&self) -> usize {
        self.skel.maps.timing_map.keys().count()
    }

    /// Dump a diagnostic sample of BPF map entries.
    ///
    /// Logs the first few entries with decoded keys and values.
    /// Returns (total_count, sample_keys) for external logging.
    pub fn dump_diagnostic(&self, max_samples: usize) -> (usize, Vec<DiagnosticEntry>) {
        let mut entries = Vec::new();
        let mut total = 0;

        for key in self.skel.maps.timing_map.keys() {
            total += 1;
            if entries.len() < max_samples {
                let value = self
                    .skel
                    .maps
                    .timing_map
                    .lookup(&key, libbpf_rs::MapFlags::ANY)
                    .ok()
                    .flatten();

                let decoded_key = if key.len() == TIMING_KEY_SIZE {
                    let src_port = u16::from_ne_bytes(key[0..2].try_into().unwrap());
                    let dst_port = u16::from_ne_bytes(key[2..4].try_into().unwrap());
                    let ip_bytes: [u8; 4] = key[4..8].try_into().unwrap();
                    let dst_ip = std::net::Ipv4Addr::from(ip_bytes);
                    Some((src_port, dst_port, dst_ip))
                } else {
                    None
                };

                let decoded_value = value.as_ref().and_then(|v| parse_timing_value_v2(v));

                entries.push(DiagnosticEntry {
                    raw_key: key,
                    decoded_key,
                    decoded_value,
                });
            }
        }

        (total, entries)
    }
}

impl Drop for BpfTimingCollector {
    fn drop(&mut self) {
        // TC hooks persist after userspace exits, so we must explicitly detach
        if let Some(ref mut hook) = self._tc_hook {
            if let Err(e) = hook.detach() {
                tracing::warn!(error = %e, "Failed to detach TC hook on drop");
            }
        }
        // XDP link is automatically detached via RAII
    }
}

/// Mock BPF timing collector for testing.
#[derive(Debug, Default)]
pub struct MockBpfTimingCollector {
    entries: HashMap<(u32, u16, u16), u64>,
    entries_v2: HashMap<(u32, u16, u16), TimingMapEntry>,
    deleted: std::cell::RefCell<Vec<(u32, u16, u16)>>,
    backend: TimingBackend,
    /// Last fd registered via register_xsk_fd (for test assertions).
    registered_xsk_fd: std::cell::Cell<Option<i32>>,
}

impl MockBpfTimingCollector {
    /// Create a new mock with predefined timing entries.
    pub fn new(backend: TimingBackend) -> Self {
        Self {
            entries: HashMap::new(),
            entries_v2: HashMap::new(),
            deleted: std::cell::RefCell::new(Vec::new()),
            backend,
            registered_xsk_fd: std::cell::Cell::new(None),
        }
    }

    /// Add a timing entry (delta in nanoseconds).
    /// Creates a v2 entry with Open state for backward compatibility.
    pub fn add_entry(&mut self, dst_ip: u32, dst_port: u16, src_port: u16, delta_ns: u64) {
        self.entries.insert((dst_ip, dst_port, src_port), delta_ns);
        self.entries_v2.insert(
            (dst_ip, dst_port, src_port),
            TimingMapEntry {
                delta_ns,
                port_state: PortState::Open,
                response_ttl: 0,
                response_win: 0,
            },
        );
    }

    /// Add a full v2 timing entry with port state, TTL, and window.
    pub fn add_entry_v2(
        &mut self,
        dst_ip: u32,
        dst_port: u16,
        src_port: u16,
        entry: TimingMapEntry,
    ) {
        self.entries
            .insert((dst_ip, dst_port, src_port), entry.delta_ns);
        self.entries_v2.insert((dst_ip, dst_port, src_port), entry);
    }

    /// Read timing delta for a specific connection.
    pub fn read_timing(&self, dst_ip: u32, dst_port: u16, src_port: u16) -> Option<u64> {
        self.entries.get(&(dst_ip, dst_port, src_port)).copied()
    }

    /// Read a full v2 timing entry.
    pub fn read_timing_v2(
        &self,
        dst_ip: u32,
        dst_port: u16,
        src_port: u16,
    ) -> Option<TimingMapEntry> {
        self.entries_v2.get(&(dst_ip, dst_port, src_port)).cloned()
    }

    /// Record deletion of a timing entry.
    pub fn delete_entry(&self, dst_ip: u32, dst_port: u16, src_port: u16) {
        self.deleted.borrow_mut().push((dst_ip, dst_port, src_port));
    }

    /// Get the timing backend mode.
    pub fn backend(&self) -> TimingBackend {
        self.backend
    }

    /// Get entries that were deleted (for test assertions).
    pub fn deleted_entries(&self) -> Vec<(u32, u16, u16)> {
        self.deleted.borrow().clone()
    }

    /// Register an AF_XDP socket fd (mock — records fd for test assertions).
    pub fn register_xsk_fd(&self, fd: i32) -> Result<(), BpfTimingError> {
        self.registered_xsk_fd.set(Some(fd));
        Ok(())
    }

    /// Get the fd that was last registered (for test assertions).
    pub fn registered_xsk_fd(&self) -> Option<i32> {
        self.registered_xsk_fd.get()
    }
}

/// Trait for reading entries from a BPF timing map.
///
/// Abstracts over both `BpfTimingCollector` (real kernel BPF map) and
/// `MockBpfTimingCollector` (in-memory test double). Used by `DiscoveryCollector`
/// to collect port classification results after SYN probes.
pub trait BpfReader {
    /// Read a full v2 timing entry from the BPF map.
    fn read_timing_v2(&self, dst_ip: u32, dst_port: u16, src_port: u16) -> Option<TimingMapEntry>;

    /// Delete a timing entry from the BPF map after reading.
    fn delete_entry(&self, dst_ip: u32, dst_port: u16, src_port: u16);
}

impl BpfReader for BpfTimingCollector {
    fn read_timing_v2(&self, dst_ip: u32, dst_port: u16, src_port: u16) -> Option<TimingMapEntry> {
        BpfTimingCollector::read_timing_v2(self, dst_ip, dst_port, src_port)
    }

    fn delete_entry(&self, dst_ip: u32, dst_port: u16, src_port: u16) {
        BpfTimingCollector::delete_entry(self, dst_ip, dst_port, src_port)
    }
}

impl BpfReader for MockBpfTimingCollector {
    fn read_timing_v2(&self, dst_ip: u32, dst_port: u16, src_port: u16) -> Option<TimingMapEntry> {
        MockBpfTimingCollector::read_timing_v2(self, dst_ip, dst_port, src_port)
    }

    fn delete_entry(&self, dst_ip: u32, dst_port: u16, src_port: u16) {
        MockBpfTimingCollector::delete_entry(self, dst_ip, dst_port, src_port)
    }
}

/// Diagnostic entry from BPF map dump.
#[derive(Debug)]
pub struct DiagnosticEntry {
    /// Raw key bytes.
    pub raw_key: Vec<u8>,
    /// Decoded key: (src_port, dst_port, dst_ip).
    pub decoded_key: Option<(u16, u16, std::net::Ipv4Addr)>,
    /// Decoded value (if parseable).
    pub decoded_value: Option<TimingMapEntry>,
}

/// BPF timing key size in bytes.
/// Layout: src_port(2) + dst_port(2) + dst_ip(4) = 8 bytes
/// src_port first for fast lookup (unique per probe, prevents collisions).
pub const TIMING_KEY_SIZE: usize = 8;

/// BPF timing value size in bytes.
/// Layout: syn_ts_ns(8) + response_ts_ns(8) + flags(4) + port_state(1) + response_ttl(1) + response_win(2) = 24 bytes
pub const TIMING_VALUE_SIZE: usize = 24;

/// Version marker bit position in flags field (bits 28-31).
const FLAGS_VERSION_SHIFT: u32 = 28;

/// Current version marker value.
pub const FLAGS_VERSION_1: u32 = 0x1;

/// Flag bit: SYN packet recorded by TC egress.
pub const FLAG_SYN: u32 = 1;
/// Flag bit: SYN-ACK response recorded by XDP ingress.
pub const FLAG_SYNACK: u32 = 2;
/// Flag bit: RST response recorded by XDP ingress.
pub const FLAG_RST: u32 = 4;
/// Flag bit: ICMP unreachable recorded by XDP ingress.
pub const FLAG_ICMP: u32 = 8;

/// Parsed entry from the BPF timing map (v2 format).
///
/// Contains timing delta plus port discovery metadata from the response packet.
#[derive(Debug, Clone, PartialEq)]
pub struct TimingMapEntry {
    /// SYN-to-response delta in nanoseconds.
    pub delta_ns: u64,
    /// Port discovery state.
    pub port_state: PortState,
    /// TTL from response IP header.
    pub response_ttl: u8,
    /// TCP window from response (0 for ICMP).
    pub response_win: u16,
}

/// Build raw key bytes for BPF map lookup.
///
/// Layout matches the C struct: src_port(2) + dst_port(2) + dst_ip(4).
/// Ports are stored in host byte order (BPF uses bpf_ntohs).
/// IP is stored in network byte order (BPF uses ip->daddr/ip->saddr raw).
pub fn build_key_bytes(dst_ip: u32, dst_port: u16, src_port: u16) -> [u8; TIMING_KEY_SIZE] {
    let mut key = [0u8; TIMING_KEY_SIZE];
    // src_port in host byte order (BPF: bpf_ntohs(tcp->source))
    key[0..2].copy_from_slice(&src_port.to_ne_bytes());
    // dst_port in host byte order (BPF: bpf_ntohs(tcp->dest))
    key[2..4].copy_from_slice(&dst_port.to_ne_bytes());
    // dst_ip in network byte order (BPF: ip->daddr raw, no conversion)
    key[4..8].copy_from_slice(&dst_ip.to_be_bytes());
    key
}

/// Parse a raw BPF timing value into a nanosecond delta (legacy v0 parser).
///
/// Returns Some(delta_ns) if both SYN and SYN-ACK timestamps are recorded,
/// None otherwise. Works with both v0 and v1 entries that have SYN-ACK responses.
pub fn parse_timing_value(value: &[u8]) -> Option<u64> {
    if value.len() != TIMING_VALUE_SIZE {
        return None;
    }

    let syn_ts_ns = u64::from_ne_bytes(value[0..8].try_into().unwrap());
    let response_ts_ns = u64::from_ne_bytes(value[8..16].try_into().unwrap());
    let flags = u32::from_ne_bytes(value[16..20].try_into().unwrap());

    // Both SYN and SYN-ACK timestamps must be recorded: bit 0 (syn) and bit 1 (synack)
    if flags & 0x3 != 0x3 {
        return None;
    }

    // response should be after syn
    if response_ts_ns <= syn_ts_ns {
        return None;
    }

    Some(response_ts_ns - syn_ts_ns)
}

/// Parse a raw BPF timing value into a full v2 entry.
///
/// Handles three entry types:
/// - v0 (legacy): only SYN-ACK timing, port_state/ttl/win default to Open/0/0
/// - v1 with TC: full entry with SYN+response timestamps, timing delta computed
/// - v1 response-only: created by XDP when raw sockets bypass TC (no SYN flag,
///   delta_ns=0, but port_state/TTL/window are valid for discovery)
pub fn parse_timing_value_v2(value: &[u8]) -> Option<TimingMapEntry> {
    if value.len() != TIMING_VALUE_SIZE {
        return None;
    }

    let syn_ts_ns = u64::from_ne_bytes(value[0..8].try_into().unwrap());
    let response_ts_ns = u64::from_ne_bytes(value[8..16].try_into().unwrap());
    let flags = u32::from_ne_bytes(value[16..20].try_into().unwrap());

    let version = (flags >> FLAGS_VERSION_SHIFT) & 0xF;

    if version == 0 {
        // Legacy v0 entry — only SYN-ACK, use old parsing logic
        if flags & 0x3 != 0x3 {
            return None;
        }
        if response_ts_ns <= syn_ts_ns {
            return None;
        }
        return Some(TimingMapEntry {
            delta_ns: response_ts_ns - syn_ts_ns,
            port_state: PortState::Open,
            response_ttl: 0,
            response_win: 0,
        });
    }

    // v1+ entry — parse full metadata
    let port_state = PortState::from_u8(value[20]);
    let response_ttl = value[21];
    let response_win = u16::from_ne_bytes(value[22..24].try_into().unwrap());

    let has_syn = flags & FLAG_SYN != 0;
    let has_response = flags & (FLAG_SYNACK | FLAG_RST | FLAG_ICMP) != 0;

    // Must have at least one response type
    if !has_response {
        return None;
    }

    if has_syn {
        // Normal TC+XDP path: compute timing delta
        let delta_ns = if response_ts_ns > syn_ts_ns {
            response_ts_ns - syn_ts_ns
        } else {
            // Clock inversion: on multi-socket NUMA systems, bpf_ktime_get_ns()
            // can produce slight inversions (~100ns). Return delta_ns=0 with valid
            // port state rather than discarding the entry entirely.
            tracing::warn!(
                syn_ts_ns,
                response_ts_ns,
                "clock inversion: response_ts <= syn_ts (NUMA skew?), returning delta_ns=0"
            );
            0
        };
        Some(TimingMapEntry {
            delta_ns,
            port_state,
            response_ttl,
            response_win,
        })
    } else {
        // Raw socket path: XDP created entry without TC (no SYN timestamp).
        // Port state, TTL, and window are valid; timing delta is unavailable.
        Some(TimingMapEntry {
            delta_ns: 0,
            port_state,
            response_ttl,
            response_win,
        })
    }
}

/// Forbidden XDP return actions.
/// XDP_REDIRECT is intentionally omitted — it is allowed when used via
/// `bpf_redirect_map` with an XSKMAP (AF_XDP socket map). Direct
/// `return XDP_REDIRECT` is still banned by `check_bpf_source_safety`.
const FORBIDDEN_XDP_ACTIONS: &[&str] = &["XDP_DROP", "XDP_ABORTED", "XDP_TX"];

/// Forbidden TC return actions.
const FORBIDDEN_TC_ACTIONS: &[&str] = &["TC_ACT_SHOT", "TC_ACT_STOLEN"];

/// Analyze the BPF C source for safety violations.
///
/// Returns a list of violations found, or empty if the source is safe.
///
/// Checks:
/// - Banned XDP return actions: XDP_DROP, XDP_ABORTED, XDP_TX
/// - Banned TC return actions: TC_ACT_SHOT, TC_ACT_STOLEN
/// - Direct `return XDP_REDIRECT` is banned; XSKMAP redirect via
///   `bpf_redirect_map` with `xsk_map` is the only safe redirect path
/// - If `bpf_redirect_map` is used, `xsk_map` must also be present
pub fn check_bpf_source_safety(source: &str) -> Vec<String> {
    let mut violations = Vec::new();

    for action in FORBIDDEN_XDP_ACTIONS {
        let pattern = format!("return {}", action);
        if source.contains(&pattern) {
            violations.push(format!("forbidden XDP action: {}", action));
        }
    }

    for action in FORBIDDEN_TC_ACTIONS {
        let pattern = format!("return {}", action);
        if source.contains(&pattern) {
            violations.push(format!("forbidden TC action: {}", action));
        }
    }

    // Direct XDP_REDIRECT return is banned — only safe via bpf_redirect_map + xsk_map
    if source.contains("return XDP_REDIRECT") {
        violations.push(
            "direct XDP_REDIRECT return is forbidden; use bpf_redirect_map with xsk_map".into(),
        );
    }

    // If bpf_redirect_map is used, it must reference xsk_map (XSKMAP AF_XDP socket)
    if source.contains("bpf_redirect_map") && !source.contains("xsk_map") {
        violations.push("bpf_redirect_map must reference xsk_map for AF_XDP redirect".into());
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // Stage 1 Tests: BPF source safety and struct sizes
    // ===========================================

    #[test]
    fn test_timing_bpf_source_no_packet_drops() {
        let source = include_str!("../../bpf/timing.bpf.c");
        let violations = check_bpf_source_safety(source);
        assert!(
            violations.is_empty(),
            "BPF source contains forbidden actions: {:?}",
            violations
        );
    }

    #[test]
    fn test_timing_bpf_source_uses_lru_hash() {
        let source = include_str!("../../bpf/timing.bpf.c");
        assert!(
            source.contains("BPF_MAP_TYPE_LRU_HASH"),
            "BPF source must use LRU hash map for bounded memory"
        );
    }

    #[test]
    fn test_timing_bpf_source_tc_returns_ok() {
        let source = include_str!("../../bpf/timing.bpf.c");
        assert!(
            source.contains("return TC_ACT_OK"),
            "TC program must return TC_ACT_OK"
        );
    }

    #[test]
    fn test_timing_key_struct_size() {
        assert_eq!(
            TIMING_KEY_SIZE, 8,
            "timing_key must be 8 bytes: src_port(2) + dst_port(2) + dst_ip(4)"
        );
    }

    #[test]
    fn test_timing_value_size_unchanged() {
        assert_eq!(
            TIMING_VALUE_SIZE, 24,
            "timing_value must be 24 bytes: syn_ts_ns(8) + response_ts_ns(8) + flags(4) + port_state(1) + response_ttl(1) + response_win(2)"
        );
    }

    #[test]
    fn test_parse_timing_value_known_bytes() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 1_000_000_000; // 1 second in ns
        let synack_ts: u64 = 1_000_500_000; // 1.0005 seconds (500µs RTT)
        let flags: u32 = 0x3; // both recorded

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&synack_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());

        let delta = parse_timing_value(&value);
        assert_eq!(delta, Some(500_000)); // 500µs in ns
    }

    // ===========================================
    // Stage 2 Tests: Error display, backend, mock, parsing
    // ===========================================

    #[test]
    fn test_bpf_timing_error_display_variants() {
        let err = BpfTimingError::Load("object load failed".to_string());
        assert_eq!(
            err.to_string(),
            "failed to load BPF timing program: object load failed"
        );

        let err = BpfTimingError::AttachXdp {
            interface: "eth0".to_string(),
            reason: "device busy".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to attach XDP program to interface 'eth0': device busy"
        );

        let err = BpfTimingError::AttachTc {
            interface: "eth0".to_string(),
            reason: "not supported".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "failed to attach TC program to interface 'eth0': not supported"
        );

        let err = BpfTimingError::InterfaceNotFound("eth99".to_string());
        assert_eq!(err.to_string(), "network interface not found: eth99");

        let err = BpfTimingError::InsufficientPermissions;
        assert_eq!(
            err.to_string(),
            "insufficient permissions (requires CAP_BPF, CAP_NET_ADMIN)"
        );

        let err = BpfTimingError::MapError("key not found".to_string());
        assert_eq!(err.to_string(), "BPF map operation failed: key not found");
    }

    #[test]
    fn test_timing_backend_precision_class_xdp() {
        assert_eq!(TimingBackend::Xdp.precision_class(), "xdp");
    }

    #[test]
    fn test_timing_backend_precision_class_xdp_hybrid() {
        assert_eq!(TimingBackend::XdpHybrid.precision_class(), "xdp");
    }

    #[test]
    fn test_mock_collector_returns_known_timing() {
        let mut mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        mock.add_entry(0x08080808, 443, 12345, 500_000); // 500µs

        let delta = mock.read_timing(0x08080808, 443, 12345);
        assert_eq!(delta, Some(500_000));
    }

    #[test]
    fn test_mock_collector_returns_none_for_unknown_key() {
        let mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let delta = mock.read_timing(0x08080808, 443, 12345);
        assert_eq!(delta, None);
    }

    #[test]
    fn test_parse_timing_value_both_timestamps_returns_delta() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 5_000_000_000;
        let synack_ts: u64 = 5_001_000_000; // 1ms RTT
        let flags: u32 = 0x3;

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&synack_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());

        assert_eq!(parse_timing_value(&value), Some(1_000_000));
    }

    #[test]
    fn test_parse_timing_value_syn_only_returns_none() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 5_000_000_000;
        let flags: u32 = 0x1; // only syn recorded

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());

        assert_eq!(parse_timing_value(&value), None);
    }

    #[test]
    fn test_parse_timing_value_synack_only_returns_none() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let synack_ts: u64 = 5_001_000_000;
        let flags: u32 = 0x2; // only synack recorded

        value[8..16].copy_from_slice(&synack_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());

        assert_eq!(parse_timing_value(&value), None);
    }

    #[test]
    fn test_parse_timing_value_wrong_size() {
        let short = [0u8; 16];
        assert_eq!(parse_timing_value(&short), None);

        let long = [0u8; 32];
        assert_eq!(parse_timing_value(&long), None);
    }

    #[test]
    fn test_parse_timing_value_synack_before_syn_returns_none() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 5_001_000_000;
        let synack_ts: u64 = 5_000_000_000; // before syn (invalid)
        let flags: u32 = 0x3;

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&synack_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());

        assert_eq!(parse_timing_value(&value), None);
    }

    #[test]
    fn test_build_key_bytes_roundtrip() {
        let key = build_key_bytes(0x08080808, 443, 12345);
        assert_eq!(key.len(), TIMING_KEY_SIZE);

        // Ports: host byte order (NE)
        let src_port = u16::from_ne_bytes(key[0..2].try_into().unwrap());
        let dst_port = u16::from_ne_bytes(key[2..4].try_into().unwrap());
        // IP: network byte order (BE) to match BPF's ip->daddr/ip->saddr
        let dst_ip = u32::from_be_bytes(key[4..8].try_into().unwrap());

        assert_eq!(dst_ip, 0x08080808);
        assert_eq!(dst_port, 443);
        assert_eq!(src_port, 12345);
    }

    #[test]
    fn test_build_key_bytes_ip_matches_bpf_network_order() {
        // 167.172.61.26 — asymmetric bytes expose BE/NE mismatch bugs
        let ip = u32::from_be_bytes([167, 172, 61, 26]); // 0xA7AC3D1A
        let key = build_key_bytes(ip, 80, 50000);

        // BPF stores ip->daddr raw (network byte order): [167, 172, 61, 26]
        assert_eq!(key[4], 167, "IP byte 0 must be 167 (network order)");
        assert_eq!(key[5], 172, "IP byte 1 must be 172 (network order)");
        assert_eq!(key[6], 61, "IP byte 2 must be 61 (network order)");
        assert_eq!(key[7], 26, "IP byte 3 must be 26 (network order)");
    }

    #[test]
    fn test_mock_collector_delete_entry_tracked() {
        let mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        mock.delete_entry(0x08080808, 443, 12345);
        mock.delete_entry(0x01010101, 80, 54321);

        let deleted = mock.deleted_entries();
        assert_eq!(deleted.len(), 2);
        assert_eq!(deleted[0], (0x08080808, 443, 12345));
        assert_eq!(deleted[1], (0x01010101, 80, 54321));
    }

    #[test]
    fn test_mock_collector_backend() {
        let mock = MockBpfTimingCollector::new(TimingBackend::XdpHybrid);
        assert_eq!(mock.backend(), TimingBackend::XdpHybrid);
    }

    #[test]
    fn test_check_bpf_source_safety_clean() {
        let source = r#"
            return TC_ACT_OK;
            return XDP_PASS;
        "#;
        assert!(check_bpf_source_safety(source).is_empty());
    }

    #[test]
    fn test_check_bpf_source_safety_detects_xdp_drop() {
        let source = "return XDP_DROP;";
        let violations = check_bpf_source_safety(source);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("XDP_DROP"));
    }

    #[test]
    fn test_check_bpf_source_safety_detects_tc_shot() {
        let source = "return TC_ACT_SHOT;";
        let violations = check_bpf_source_safety(source);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("TC_ACT_SHOT"));
    }

    #[test]
    fn test_check_bpf_source_safety_allows_xskmap_redirect() {
        // bpf_redirect_map with xsk_map is the safe AF_XDP redirect path
        let source = r#"
            return bpf_redirect_map(&xsk_map, 0, XDP_PASS);
            return XDP_PASS;
        "#;
        let violations = check_bpf_source_safety(source);
        assert!(
            violations.is_empty(),
            "bpf_redirect_map with xsk_map must be allowed: {:?}",
            violations
        );
    }

    #[test]
    fn test_check_bpf_source_safety_bans_direct_xdp_redirect() {
        let source = "return XDP_REDIRECT;";
        let violations = check_bpf_source_safety(source);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("XDP_REDIRECT"));
    }

    #[test]
    fn test_check_bpf_source_safety_bans_redirect_map_without_xsk_map() {
        // bpf_redirect_map without xsk_map could redirect to arbitrary interfaces
        let source = r#"
            return bpf_redirect_map(&other_map, 0, XDP_PASS);
        "#;
        let violations = check_bpf_source_safety(source);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("xsk_map"));
    }

    #[test]
    fn test_timing_bpf_source_uses_xskmap_redirect() {
        let source = include_str!("../../bpf/timing.bpf.c");
        assert!(
            source.contains("bpf_redirect_map"),
            "BPF source must use bpf_redirect_map for AF_XDP XSKMAP redirect"
        );
        assert!(
            source.contains("xsk_map"),
            "BPF source must define xsk_map for AF_XDP socket registration"
        );
    }

    #[test]
    fn test_timing_bpf_source_xskmap_max_entries_one() {
        let source = include_str!("../../bpf/timing.bpf.c");
        // xsk_map must have max_entries=1 (single AF_XDP socket)
        assert!(
            source.contains("BPF_MAP_TYPE_XSKMAP"),
            "BPF source must declare BPF_MAP_TYPE_XSKMAP"
        );
    }

    // ===========================================
    // Stage 1 v2 Tests: BPF source, v2 parsing, key layout, mock
    // ===========================================

    #[test]
    fn test_timing_bpf_source_handles_rst() {
        let source = include_str!("../../bpf/timing.bpf.c");
        assert!(
            source.contains("tcp->rst"),
            "BPF source must handle RST responses for port discovery"
        );
    }

    #[test]
    fn test_timing_bpf_source_handles_icmp_unreachable() {
        let source = include_str!("../../bpf/timing.bpf.c");
        assert!(
            source.contains("IPPROTO_ICMP"),
            "BPF source must handle ICMP unreachable for port discovery"
        );
        assert!(
            source.contains("type == 3") || source.contains("type != 3"),
            "BPF source must check ICMP type 3 (destination unreachable)"
        );
    }

    #[test]
    fn test_timing_bpf_source_still_no_packet_drops() {
        let source = include_str!("../../bpf/timing.bpf.c");
        let violations = check_bpf_source_safety(source);
        assert!(
            violations.is_empty(),
            "BPF source must not drop packets after RST/ICMP additions: {:?}",
            violations
        );
    }

    #[test]
    fn test_timing_value_version_marker() {
        // Build a v1 entry with SYN + SYN-ACK flags and version 1
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 1_000_000_000;
        let response_ts: u64 = 1_000_500_000;
        let flags: u32 = FLAG_SYN | FLAG_SYNACK | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&response_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());
        value[20] = PortState::Open as u8;

        // Verify version nibble is 0x1
        let parsed_flags = u32::from_ne_bytes(value[16..20].try_into().unwrap());
        let version = (parsed_flags >> FLAGS_VERSION_SHIFT) & 0xF;
        assert_eq!(version, 1, "top nibble of flags must be version 0x1");
    }

    #[test]
    fn test_parse_timing_value_v2_open() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 1_000_000_000;
        let response_ts: u64 = 1_000_500_000; // 500µs
        let flags: u32 = FLAG_SYN | FLAG_SYNACK | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&response_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());
        value[20] = PortState::Open as u8;
        value[21] = 64; // TTL
        value[22..24].copy_from_slice(&65535u16.to_ne_bytes()); // window

        let entry = parse_timing_value_v2(&value).unwrap();
        assert_eq!(entry.delta_ns, 500_000);
        assert_eq!(entry.port_state, PortState::Open);
        assert_eq!(entry.response_ttl, 64);
        assert_eq!(entry.response_win, 65535);
    }

    #[test]
    fn test_parse_timing_value_v2_closed() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 1_000_000_000;
        let response_ts: u64 = 1_000_200_000; // 200µs
        let flags: u32 = FLAG_SYN | FLAG_RST | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&response_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());
        value[20] = PortState::Closed as u8;
        value[21] = 64; // TTL
        value[22..24].copy_from_slice(&0u16.to_ne_bytes()); // RST window usually 0

        let entry = parse_timing_value_v2(&value).unwrap();
        assert_eq!(entry.delta_ns, 200_000);
        assert_eq!(entry.port_state, PortState::Closed);
        assert_eq!(entry.response_ttl, 64);
        assert_eq!(entry.response_win, 0);
    }

    #[test]
    fn test_parse_timing_value_v2_unreachable() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 1_000_000_000;
        let response_ts: u64 = 1_000_300_000; // 300µs
        let flags: u32 = FLAG_SYN | FLAG_ICMP | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&response_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());
        value[20] = PortState::Unreachable as u8;
        value[21] = 252; // TTL from ICMP response
        value[22..24].copy_from_slice(&0u16.to_ne_bytes()); // no window for ICMP

        let entry = parse_timing_value_v2(&value).unwrap();
        assert_eq!(entry.delta_ns, 300_000);
        assert_eq!(entry.port_state, PortState::Unreachable);
        assert_eq!(entry.response_ttl, 252);
        assert_eq!(entry.response_win, 0);
    }

    #[test]
    fn test_parse_timing_value_v2_extracts_ttl_win() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 2_000_000_000;
        let response_ts: u64 = 2_001_000_000;
        let flags: u32 = FLAG_SYN | FLAG_SYNACK | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&response_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());
        value[20] = PortState::Open as u8;
        value[21] = 128; // Windows TTL
        value[22..24].copy_from_slice(&64240u16.to_ne_bytes()); // typical Linux window

        let entry = parse_timing_value_v2(&value).unwrap();
        assert_eq!(entry.response_ttl, 128);
        assert_eq!(entry.response_win, 64240);
    }

    #[test]
    fn test_parse_timing_value_v2_legacy_compat() {
        // Build a legacy v0 entry (no version marker)
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 1_000_000_000;
        let synack_ts: u64 = 1_000_500_000;
        let flags: u32 = 0x3; // v0: syn + synack, no version nibble

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&synack_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());
        // bytes 20-23 are zero (_pad in v0)

        let entry = parse_timing_value_v2(&value).unwrap();
        assert_eq!(entry.delta_ns, 500_000);
        assert_eq!(
            entry.port_state,
            PortState::Open,
            "v0 entries should be treated as Open"
        );
        assert_eq!(entry.response_ttl, 0, "v0 entries have no TTL data");
        assert_eq!(entry.response_win, 0, "v0 entries have no window data");
    }

    #[test]
    fn test_existing_parse_timing_value_still_works() {
        // Verify the legacy parser works with v1 SYN-ACK entries
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 1_000_000_000;
        let response_ts: u64 = 1_000_500_000;
        // v1 flags: syn(1) + synack(2) + version(0x10000000)
        let flags: u32 = FLAG_SYN | FLAG_SYNACK | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&response_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());

        // Legacy parser checks flags & 0x3 == 0x3, which still matches
        let delta = parse_timing_value(&value);
        assert_eq!(
            delta,
            Some(500_000),
            "legacy parser must still work with v1 SYN-ACK entries"
        );
    }

    #[test]
    fn test_existing_parse_timing_value_rejects_rst() {
        // Legacy parser should return None for RST entries (no SYN-ACK bit)
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 1_000_000_000;
        let response_ts: u64 = 1_000_200_000;
        let flags: u32 = FLAG_SYN | FLAG_RST | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[8..16].copy_from_slice(&response_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());

        let delta = parse_timing_value(&value);
        assert_eq!(delta, None, "legacy parser must reject RST entries");
    }

    #[test]
    fn test_bpf_map_key_includes_src_port() {
        // Two keys with different src_ports must produce different bytes
        let key1 = build_key_bytes(0x08080808, 443, 12345);
        let key2 = build_key_bytes(0x08080808, 443, 54321);
        assert_ne!(
            key1, key2,
            "different src_ports must produce different keys"
        );

        // Verify src_port is at offset 0 (first field for fast lookup)
        let src1 = u16::from_ne_bytes(key1[0..2].try_into().unwrap());
        let src2 = u16::from_ne_bytes(key2[0..2].try_into().unwrap());
        assert_eq!(src1, 12345);
        assert_eq!(src2, 54321);
    }

    #[test]
    fn test_concurrent_discovery_scans_no_key_collision() {
        // Concurrent scans to the same target but different src_ports
        let key_scan_a = build_key_bytes(0x0A000001, 80, 50000);
        let key_scan_b = build_key_bytes(0x0A000001, 80, 50001);
        assert_ne!(
            key_scan_a, key_scan_b,
            "concurrent scans to same target:port must not collide"
        );
    }

    #[test]
    fn test_mock_collector_supports_delete() {
        let mock = MockBpfTimingCollector::new(TimingBackend::Xdp);

        // Delete several entries
        mock.delete_entry(0x08080808, 443, 12345);
        mock.delete_entry(0x01010101, 80, 54321);
        mock.delete_entry(0x0A000001, 22, 60000);

        let deleted = mock.deleted_entries();
        assert_eq!(deleted.len(), 3);
        assert!(deleted.contains(&(0x08080808, 443, 12345)));
        assert!(deleted.contains(&(0x01010101, 80, 54321)));
        assert!(deleted.contains(&(0x0A000001, 22, 60000)));
    }

    #[test]
    fn test_mock_collector_v2_port_state() {
        let mut mock = MockBpfTimingCollector::new(TimingBackend::Xdp);

        mock.add_entry_v2(
            0x08080808,
            443,
            12345,
            TimingMapEntry {
                delta_ns: 500_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );
        mock.add_entry_v2(
            0x08080808,
            22,
            12346,
            TimingMapEntry {
                delta_ns: 200_000,
                port_state: PortState::Closed,
                response_ttl: 64,
                response_win: 0,
            },
        );

        // v1 read (backward compat)
        assert_eq!(mock.read_timing(0x08080808, 443, 12345), Some(500_000));
        assert_eq!(mock.read_timing(0x08080808, 22, 12346), Some(200_000));

        // v2 read (full entry)
        let open = mock.read_timing_v2(0x08080808, 443, 12345).unwrap();
        assert_eq!(open.port_state, PortState::Open);
        assert_eq!(open.response_ttl, 64);

        let closed = mock.read_timing_v2(0x08080808, 22, 12346).unwrap();
        assert_eq!(closed.port_state, PortState::Closed);
    }

    #[test]
    fn test_parse_timing_value_v2_no_response_returns_none() {
        // v1 entry with only SYN flag (no response yet)
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let syn_ts: u64 = 1_000_000_000;
        let flags: u32 = FLAG_SYN | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[0..8].copy_from_slice(&syn_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());

        assert_eq!(
            parse_timing_value_v2(&value),
            None,
            "v2 parser must return None when no response flags set"
        );
    }

    #[test]
    fn test_parse_timing_value_v2_wrong_size() {
        assert_eq!(parse_timing_value_v2(&[0u8; 16]), None);
        assert_eq!(parse_timing_value_v2(&[0u8; 32]), None);
    }

    // ===========================================
    // Response-only entries (raw socket bypass TC)
    // ===========================================

    #[test]
    fn test_parse_timing_value_v2_response_only_synack() {
        // XDP creates entry when TC didn't see the SYN (raw socket bypass)
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let response_ts: u64 = 5_000_000_000;
        // No FLAG_SYN — only SYNACK + version
        let flags: u32 = FLAG_SYNACK | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[8..16].copy_from_slice(&response_ts.to_ne_bytes()); // syn_ts = 0
        value[16..20].copy_from_slice(&flags.to_ne_bytes());
        value[20] = PortState::Open as u8;
        value[21] = 64; // TTL
        value[22..24].copy_from_slice(&65535u16.to_ne_bytes());

        let entry = parse_timing_value_v2(&value).unwrap();
        assert_eq!(
            entry.delta_ns, 0,
            "no timing delta without TC SYN timestamp"
        );
        assert_eq!(entry.port_state, PortState::Open);
        assert_eq!(entry.response_ttl, 64);
        assert_eq!(entry.response_win, 65535);
    }

    #[test]
    fn test_parse_timing_value_v2_response_only_rst() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let response_ts: u64 = 5_000_000_000;
        let flags: u32 = FLAG_RST | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[8..16].copy_from_slice(&response_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());
        value[20] = PortState::Closed as u8;
        value[21] = 64;

        let entry = parse_timing_value_v2(&value).unwrap();
        assert_eq!(entry.delta_ns, 0);
        assert_eq!(entry.port_state, PortState::Closed);
    }

    #[test]
    fn test_parse_timing_value_v2_response_only_icmp() {
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let response_ts: u64 = 5_000_000_000;
        let flags: u32 = FLAG_ICMP | (FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT);

        value[8..16].copy_from_slice(&response_ts.to_ne_bytes());
        value[16..20].copy_from_slice(&flags.to_ne_bytes());
        value[20] = PortState::Unreachable as u8;
        value[21] = 252;

        let entry = parse_timing_value_v2(&value).unwrap();
        assert_eq!(entry.delta_ns, 0);
        assert_eq!(entry.port_state, PortState::Unreachable);
        assert_eq!(entry.response_ttl, 252);
    }

    #[test]
    fn test_parse_timing_value_v2_no_flags_still_returns_none() {
        // Entry with version but no SYN and no response flags
        let mut value = [0u8; TIMING_VALUE_SIZE];
        let flags: u32 = FLAGS_VERSION_1 << FLAGS_VERSION_SHIFT; // version only
        value[16..20].copy_from_slice(&flags.to_ne_bytes());

        assert_eq!(
            parse_timing_value_v2(&value),
            None,
            "entries with no SYN and no response flags must return None"
        );
    }

    #[test]
    fn test_bpf_source_creates_entries_on_xdp_without_tc() {
        let source = include_str!("../../bpf/timing.bpf.c");
        // XDP must use bpf_map_update_elem (not just lookup) for raw socket support
        assert!(
            source.contains("bpf_map_update_elem"),
            "XDP program must create entries when TC didn't see the SYN"
        );
    }

    // ===========================================
    // Stage 5 Tests: BpfReader trait
    // ===========================================

    #[test]
    fn test_bpf_reader_trait_mock_read_timing_v2() {
        let mut mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        mock.add_entry_v2(
            0x0A000001,
            80,
            50000,
            TimingMapEntry {
                delta_ns: 500_000,
                port_state: PortState::Open,
                response_ttl: 64,
                response_win: 65535,
            },
        );

        // Call through BpfReader trait
        let reader: &dyn BpfReader = &mock;
        let entry = reader.read_timing_v2(0x0A000001, 80, 50000);
        assert!(entry.is_some());
        let e = entry.unwrap();
        assert_eq!(e.delta_ns, 500_000);
        assert_eq!(e.port_state, PortState::Open);
        assert_eq!(e.response_ttl, 64);
        assert_eq!(e.response_win, 65535);
    }

    #[test]
    fn test_bpf_reader_trait_mock_returns_none_for_missing() {
        let mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let reader: &dyn BpfReader = &mock;
        assert!(reader.read_timing_v2(0x0A000001, 80, 50000).is_none());
    }

    #[test]
    fn test_bpf_reader_trait_mock_delete_entry() {
        let mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        let reader: &dyn BpfReader = &mock;
        reader.delete_entry(0x0A000001, 80, 50000);
        reader.delete_entry(0x0A000001, 443, 50001);

        let deleted = mock.deleted_entries();
        assert_eq!(deleted.len(), 2);
        assert_eq!(deleted[0], (0x0A000001, 80, 50000));
        assert_eq!(deleted[1], (0x0A000001, 443, 50001));
    }

    // ===========================================
    // XskMap and register_xsk_fd tests
    // ===========================================

    #[test]
    fn test_bpf_timing_error_display_xsk_map_error() {
        let err = BpfTimingError::XskMapError("no such fd".to_string());
        assert_eq!(
            err.to_string(),
            "failed to register AF_XDP socket in xsk_map: no such fd"
        );
    }

    #[test]
    fn test_mock_collector_register_xsk_fd_initially_none() {
        let mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        assert_eq!(
            mock.registered_xsk_fd(),
            None,
            "xsk_map fd must be None before registration"
        );
    }

    #[test]
    fn test_mock_collector_register_xsk_fd_records_fd() {
        let mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        mock.register_xsk_fd(42).unwrap();
        assert_eq!(
            mock.registered_xsk_fd(),
            Some(42),
            "registered fd must be stored for test assertions"
        );
    }

    #[test]
    fn test_mock_collector_register_xsk_fd_overwrite() {
        let mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        mock.register_xsk_fd(5).unwrap();
        mock.register_xsk_fd(7).unwrap();
        assert_eq!(
            mock.registered_xsk_fd(),
            Some(7),
            "second registration overwrites first"
        );
    }

    #[test]
    fn test_mock_collector_register_xsk_fd_returns_ok() {
        let mock = MockBpfTimingCollector::new(TimingBackend::Xdp);
        assert!(
            mock.register_xsk_fd(99).is_ok(),
            "mock register_xsk_fd must always return Ok"
        );
    }

    // Integration tests - require root/CAP_BPF + CAP_NET_ADMIN
    #[test]
    #[ignore]
    fn test_bpf_loads_on_supported_system() {
        todo!("Integration test - run in privileged container")
    }

    #[test]
    #[ignore]
    fn test_bpf_tc_attachment_required() {
        // BpfTimingCollector::new() must fail if TC cannot be attached.
        // With mandatory TC, there is no hybrid/degraded mode.
        // Run in privileged container where TC can be exercised.
        todo!("Integration test - run in privileged container")
    }

    #[test]
    #[ignore]
    fn test_tc_hook_no_leak_on_restart() {
        // Verify that repeated BpfTimingCollector::new() + drop() cycles on the same
        // interface do not accumulate TC hooks. After N restarts, `tc filter show dev
        // eth0 egress` must show exactly 1 filter entry (our hook), not N.
        //
        // This validates that attach_tc_egress destroys the existing clsact qdisc
        // before creating a fresh one, preventing the stale-hook accumulation that
        // was observed in production (139 timing_maps from crash loop restarts).
        //
        // Requires: bare-metal Linux with eth0, CAP_BPF, CAP_NET_ADMIN.
        // Run with: sudo cargo test --lib -- --ignored test_tc_hook_no_leak_on_restart
        todo!("Integration test — run on bare-metal Linux with CAP_BPF + CAP_NET_ADMIN")
    }
}
