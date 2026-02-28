//! Hybrid sender: raw socket TX + AF_XDP RX for kernel-level SYN timestamps.
//!
//! AF_XDP TX bypasses the kernel networking stack entirely — packets go from
//! userspace UMEM straight to the NIC driver via DMA. This means the TC egress
//! hook (which timestamps outgoing SYNs via `bpf_ktime_get_ns()`) never fires,
//! producing `syn_ts_ns = 0` and no RTT delta.
//!
//! **Solution:** Route outgoing SYNs through the kernel stack via a raw socket,
//! where TC egress can intercept and timestamp them. Incoming responses are
//! still captured via AF_XDP RX (with xsk_map redirect suppressing kernel RSTs).
//!
//! ```text
//! TX: RawSocket → sendto() → kernel IP stack → TC egress [bpf_ktime_get_ns()] → NIC
//! RX: NIC → XDP ingress [bpf_ktime_get_ns()] → xsk_map redirect → AF_XDP socket
//! RTT = response_ts_ns - syn_ts_ns  (both kernel nanosecond timestamps)
//! ```
//!
//! Jitter between `sendto()` and the TC hook is ~1–3µs (kernel-internal, no
//! scheduling involved). Both timestamps use the same `bpf_ktime_get_ns()` clock.

#[cfg(target_os = "linux")]
use std::any::Any;
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use crate::scanner::afxdp_sender::{AfXdpSend, AfXdpSender, RxFrame};
#[cfg(target_os = "linux")]
use crate::scanner::raw_socket_sender::RawSocketSender;
#[cfg(target_os = "linux")]
use crate::scanner::syn_sender::ScanError;

/// Hybrid sender combining raw socket TX with AF_XDP RX.
///
/// - **TX path**: `RawSocketSender` — SYN packets traverse the kernel IP stack,
///   allowing the TC egress BPF program to stamp `syn_ts_ns` in the timing map.
/// - **RX path**: `AfXdpSender` — the XDP ingress program timestamps responses
///   with `response_ts_ns` and redirects them via xsk_map, suppressing kernel RSTs.
///
/// The AF_XDP sender's TX ring is allocated but never used; only its UMEM, fill
/// ring, and RX ring are active.
#[cfg(target_os = "linux")]
pub struct HybridSender {
    raw_tx: RawSocketSender,
    xdp_rx: AfXdpSender,
}

#[cfg(target_os = "linux")]
impl HybridSender {
    /// Create a new hybrid sender.
    ///
    /// 1. Creates an `AfXdpSender` for RX (full AF_XDP socket with UMEM, all 4 rings).
    /// 2. Creates a `RawSocketSender` for TX (kernel stack path for TC timestamps).
    ///
    /// # Errors
    /// Returns `ScanError` if either AF_XDP socket or raw socket creation fails.
    pub fn new(ifname: &str, queue_id: u32, src_ip: Ipv4Addr) -> Result<Self, ScanError> {
        let xdp_rx = AfXdpSender::new(ifname, queue_id, src_ip)?;
        let raw_tx = RawSocketSender::new(src_ip, Some(ifname))?;
        Ok(Self { raw_tx, xdp_rx })
    }

    /// Return the AF_XDP socket file descriptor for xsk_map registration.
    ///
    /// The XDP ingress program uses xsk_map to redirect matching packets to this
    /// socket's RX ring, preventing them from reaching the kernel stack (which
    /// would send RSTs for the unsolicited SYN-ACKs).
    pub fn fd(&self) -> i32 {
        self.xdp_rx.fd()
    }
}

#[cfg(target_os = "linux")]
impl AfXdpSend for HybridSender {
    /// Send a raw IPv4 packet via the kernel stack (raw socket).
    ///
    /// The packet traverses the kernel IP stack where the TC egress BPF program
    /// intercepts it and records `syn_ts_ns` in the timing map. This is the key
    /// difference from `AfXdpSender::send_raw()` which bypasses TC entirely.
    fn send_raw(&mut self, packet: &[u8]) -> Result<(), ScanError> {
        self.raw_tx.send_raw(packet)
    }

    /// Poll the AF_XDP RX ring for incoming response frames.
    ///
    /// Returns frames redirected by the XDP ingress program via xsk_map. The BPF
    /// program has already recorded `response_ts_ns` in the timing map before
    /// redirecting the packet here.
    fn poll_rx(&mut self, timeout_ms: u64) -> Vec<RxFrame> {
        self.xdp_rx.poll_rx(timeout_ms)
    }

    /// Return the source IP address (passthrough from the raw socket sender).
    fn source_ip(&self) -> Ipv4Addr {
        self.raw_tx.source_ip()
    }

    /// Returns `true` — the AF_XDP RX ring is active and delivers response frames.
    fn has_rx(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::mem::ManuallyDrop;
    use std::net::Ipv4Addr;

    /// Construct a HybridSender for unit testing without kernel privileges.
    ///
    /// The `RawSocketSender` uses fd=-1 (safe: `Drop` skips `close()` for fd < 0).
    /// The `AfXdpSender` is zeroed and wrapped in `ManuallyDrop` to prevent its
    /// `Drop` from running (which would call `munmap`/`close` on invalid pointers/fd).
    ///
    /// Only `raw_tx`-delegated methods (`source_ip`, `has_rx`) are safe to call.
    /// Do NOT call `poll_rx` or `fd()` on the returned sender — those touch the
    /// zeroed `AfXdpSender` internals.
    fn make_test_sender(src_ip: Ipv4Addr) -> ManuallyDrop<HybridSender> {
        ManuallyDrop::new(HybridSender {
            raw_tx: RawSocketSender {
                fd: -1,
                src_ip,
            },
            // SAFETY: zeroed AfXdpSender is never used (only raw_tx methods called)
            // and ManuallyDrop prevents Drop from running on the invalid pointers.
            xdp_rx: unsafe { std::mem::zeroed() },
        })
    }

    #[test]
    fn test_hybrid_sender_has_rx_true() {
        let sender = make_test_sender(Ipv4Addr::new(10, 0, 0, 1));
        assert!(
            sender.has_rx(),
            "HybridSender must report has_rx=true — AF_XDP RX ring is active"
        );
    }

    #[test]
    fn test_hybrid_sender_source_ip() {
        let ip = Ipv4Addr::new(192, 168, 88, 1);
        let sender = make_test_sender(ip);
        assert_eq!(
            sender.source_ip(),
            ip,
            "source_ip() must return the IP configured at construction (passthrough from raw_tx)"
        );
    }

    #[test]
    fn test_hybrid_sender_source_ip_various() {
        for (a, b, c, d) in [(10, 0, 0, 1), (172, 16, 0, 1), (192, 168, 1, 1)] {
            let ip = Ipv4Addr::new(a, b, c, d);
            let sender = make_test_sender(ip);
            assert_eq!(sender.source_ip(), ip);
        }
    }

    #[test]
    fn test_hybrid_sender_implements_afxdp_send() {
        let sender = make_test_sender(Ipv4Addr::new(10, 0, 0, 1));
        // Verify HybridSender can be used as &dyn AfXdpSend (trait object dispatch)
        let trait_ref: &dyn AfXdpSend = &*sender;
        assert!(trait_ref.has_rx());
        let _ = trait_ref.source_ip();
    }

    #[test]
    #[ignore] // Requires CAP_NET_ADMIN + CAP_NET_RAW — run with: sudo cargo test --lib -- --ignored
    fn test_hybrid_sender_real_creation() {
        let result = HybridSender::new("lo", 0, Ipv4Addr::new(127, 0, 0, 1));
        assert!(
            result.is_ok(),
            "HybridSender creation should succeed with CAP_NET_ADMIN + CAP_NET_RAW: {:?}",
            result.err()
        );
        let sender = result.unwrap();
        assert!(
            sender.fd() > 0,
            "AF_XDP fd must be positive after successful creation"
        );
        assert!(sender.has_rx(), "has_rx must be true for real HybridSender");
        assert_eq!(sender.source_ip(), Ipv4Addr::new(127, 0, 0, 1));
    }
}
