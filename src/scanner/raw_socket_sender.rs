//! Raw socket TX fallback for environments where AF_XDP UMEM is unavailable.
//!
//! Used when AF_XDP fails (e.g. Apple Virtualization Framework virtio-net,
//! Docker Desktop). Sends SYN probes via `SOCK_RAW / IPPROTO_RAW` which
//! accepts raw IPv4 packets exactly as produced by `build_syn_packet()`.
//!
//! **Degraded mode**: timing precision is ~100–1000 µs jitter vs <10 µs for
//! AF_XDP. The XDP ingress BPF program continues running and timestamps
//! responses in the BPF map (emits `XDP_PASS` without xsk_map registration).
//! BPF map polling for response classification is unchanged.
//!
//! **For test/dev only.** Deploy bare-metal Linux with an XDP-capable NIC for
//! production use.

#[cfg(target_os = "linux")]
use std::any::Any;
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;

#[cfg(target_os = "linux")]
use crate::scanner::afxdp_sender::{AfXdpSend, RxFrame};
#[cfg(target_os = "linux")]
use crate::scanner::syn_sender::ScanError;

/// Raw socket sender implementing the `AfXdpSend` trait via `SOCK_RAW / IPPROTO_RAW`.
///
/// Requires `CAP_NET_RAW` (satisfied by existing `sudo` invocation).
/// `IPPROTO_RAW` implicitly sets `IP_HDRINCL` — the kernel uses the IPv4 header
/// provided by the caller verbatim, which is exactly the output of `build_syn_packet()`.
///
/// RX (response capture) is always delegated to the BPF map — `poll_rx` returns
/// an empty vec unconditionally. Without xsk_map registration the XDP ingress
/// program emits `XDP_PASS`, so responses traverse the kernel stack normally and
/// are captured by the BPF timing map via the TC hook (unchanged path).
#[cfg(target_os = "linux")]
pub struct RawSocketSender {
    fd: i32,
    src_ip: Ipv4Addr,
}

#[cfg(target_os = "linux")]
// SAFETY: RawSocketSender owns a single file descriptor; no interior mutability.
unsafe impl Send for RawSocketSender {}

#[cfg(target_os = "linux")]
impl RawSocketSender {
    /// Create a raw socket sender for the given source IP.
    ///
    /// Opens `SOCK_RAW / IPPROTO_RAW`. Requires `CAP_NET_RAW`.
    ///
    /// # Errors
    /// Returns `ScanError::RawSocket` if `socket()` fails (typically missing
    /// `CAP_NET_RAW` or kernel restriction).
    pub fn new(src_ip: Ipv4Addr) -> Result<Self, ScanError> {
        let fd = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)
        };
        if fd < 0 {
            return Err(ScanError::RawSocket(format!(
                "SOCK_RAW/IPPROTO_RAW socket creation failed (requires CAP_NET_RAW): {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { fd, src_ip })
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawSocketSender {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(target_os = "linux")]
impl AfXdpSend for RawSocketSender {
    /// Send a raw IPv4 packet via `SOCK_RAW`.
    ///
    /// `packet` must be a complete, checksummed IPv4+TCP packet as produced by
    /// `build_syn_packet()` (no Ethernet header). The destination IP is read
    /// from bytes 16–19 of the IPv4 destination address field.
    fn send_raw(&mut self, packet: &[u8]) -> Result<(), ScanError> {
        if packet.len() < 20 {
            return Err(ScanError::Send(format!(
                "packet too short for IPv4 header: {} bytes (need >= 20)",
                packet.len()
            )));
        }

        // Extract destination IP from IPv4 header bytes 16–19.
        // Store as network-byte-order u32: u32::from_ne_bytes([a,b,c,d]) on any
        // platform interprets [a,b,c,d] as memory bytes, which is what sin_addr
        // expects (sin_addr.s_addr is always stored in network byte order in memory).
        let dst_addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([packet[16], packet[17], packet[18], packet[19]]),
            },
            sin_zero: [0; 8],
        };

        let ret = unsafe {
            libc::sendto(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &dst_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(ScanError::Send(format!(
                "raw socket sendto failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }

    /// Always returns an empty vec.
    ///
    /// RX is handled by the BPF timing map (polled by `BpfTimingCollector`),
    /// not by the raw socket. Without xsk_map registration the XDP ingress
    /// program emits `XDP_PASS` and responses are timestamped via the TC hook.
    fn poll_rx(&mut self, _timeout_ms: u64) -> Vec<RxFrame> {
        vec![]
    }

    /// Return the source IP address configured at construction time.
    fn source_ip(&self) -> Ipv4Addr {
        self.src_ip
    }

    /// Raw socket fallback has no AF_XDP RX ring.
    ///
    /// Returns `false` so the caller selects the TCP connect timing path
    /// (`collect_timing_samples`) rather than the AF_XDP RX poll path
    /// (`collect_timing_samples_raw`). BPF map timestamps are still collected
    /// via the TC hook; only the RX notification mechanism differs.
    fn has_rx(&self) -> bool {
        false
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
    use std::net::Ipv4Addr;

    /// Create a RawSocketSender without opening a real socket (fd=-1).
    /// Drop will skip close() for fd < 0, so this is safe in unprivileged tests.
    fn make_test_sender(src_ip: Ipv4Addr) -> RawSocketSender {
        RawSocketSender { fd: -1, src_ip }
    }

    #[test]
    fn test_raw_socket_sender_poll_rx_always_empty() {
        let mut sender = make_test_sender(Ipv4Addr::new(10, 0, 0, 1));
        let frames = sender.poll_rx(0);
        assert!(
            frames.is_empty(),
            "poll_rx with timeout=0 must return empty vec (BPF map handles RX)"
        );
        let frames = sender.poll_rx(100);
        assert!(
            frames.is_empty(),
            "poll_rx with timeout=100 must also return empty vec"
        );
    }

    #[test]
    fn test_raw_socket_sender_source_ip() {
        let ip = Ipv4Addr::new(192, 168, 100, 50);
        let sender = make_test_sender(ip);
        assert_eq!(
            sender.source_ip(),
            ip,
            "source_ip() must return the IP configured at construction"
        );
    }

    #[test]
    fn test_raw_socket_sender_source_ip_various() {
        for (a, b, c, d) in [(10, 0, 0, 1), (172, 16, 0, 1), (192, 168, 1, 1)] {
            let ip = Ipv4Addr::new(a, b, c, d);
            let sender = make_test_sender(ip);
            assert_eq!(sender.source_ip(), ip);
        }
    }

    #[test]
    fn test_raw_socket_sender_has_rx_false() {
        let sender = make_test_sender(Ipv4Addr::new(10, 0, 0, 1));
        assert!(
            !sender.has_rx(),
            "RawSocketSender must report has_rx=false — BPF map handles RX, not AF_XDP ring"
        );
    }

    #[test]
    fn test_raw_socket_sender_has_rx_false_via_trait_object() {
        let sender: Box<dyn AfXdpSend> = Box::new(make_test_sender(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(
            !sender.has_rx(),
            "has_rx must return false through trait object dispatch"
        );
    }

    #[test]
    fn test_raw_socket_sender_implements_afxdp_send_trait() {
        // Verify RawSocketSender can be used as Box<dyn AfXdpSend>
        let sender: Box<dyn AfXdpSend> = Box::new(make_test_sender(Ipv4Addr::new(10, 0, 0, 1)));
        // poll_rx and source_ip accessible via trait object
        let _ = sender.source_ip();
    }

    #[test]
    #[ignore] // Requires CAP_NET_RAW — run with: sudo cargo test --lib -- --ignored
    fn test_raw_socket_sender_opens_socket() {
        let result = RawSocketSender::new(Ipv4Addr::new(127, 0, 0, 1));
        assert!(
            result.is_ok(),
            "raw socket creation should succeed with CAP_NET_RAW: {:?}",
            result.err()
        );
        let sender = result.unwrap();
        assert!(sender.fd >= 0, "fd must be non-negative after successful creation");
    }
}
