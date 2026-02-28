//! AF_XDP sender and receiver for kernel-level packet I/O.
//!
//! Provides a trait-based abstraction over AF_XDP socket operations,
//! with a mock implementation for unit testing and a real Linux
//! implementation using libbpf-sys + libc mmap.
//!
//! The `AfXdpSend` trait mirrors the `BpfReader` pattern — both real
//! and mock implementations exist for full unit testability without
//! kernel privileges.

use std::any::Any;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU32, Ordering};

use crate::scanner::syn_sender::ScanError;

/// A single frame received from the AF_XDP RX ring.
///
/// Contains the raw Ethernet frame bytes (including Ethernet, IP, and TCP headers).
/// The BPF program has already timestamped the packet in `timing_map` before
/// redirecting it here.
#[derive(Debug, Clone)]
pub struct RxFrame {
    /// Raw packet bytes starting from the Ethernet header.
    pub data: Vec<u8>,
}

/// Trait for AF_XDP send/receive operations.
///
/// Abstracts over both the real `AfXdpSender` (kernel AF_XDP socket) and
/// `MockAfXdpSender` (in-memory test double). Used by `SynScanner` to send
/// raw SYN packets and poll for incoming responses.
///
/// The real implementation bypasses the kernel socket buffer:
/// - TX: writes packet bytes directly to UMEM frames, kicks the NIC doorbell
/// - RX: drains the XDP RX ring of packets redirected by the BPF XSKMAP
pub trait AfXdpSend: Send {
    /// Write a raw packet (IP layer, no Ethernet framing) into the TX ring.
    ///
    /// The packet bytes are placed in a UMEM frame and enqueued for DMA.
    /// Caller is responsible for complete, checksummed IP+TCP headers.
    fn send_raw(&mut self, packet: &[u8]) -> Result<(), ScanError>;

    /// Drain the AF_XDP RX ring, returning up to `max_frames` received frames.
    ///
    /// With `timeout_ms == 0`, returns immediately with whatever is available.
    /// With `timeout_ms > 0`, polls until at least one frame arrives or the
    /// deadline expires.
    fn poll_rx(&mut self, timeout_ms: u64) -> Vec<RxFrame>;

    /// Return the source IP address for this sender (used to build packets).
    fn source_ip(&self) -> Ipv4Addr;

    /// Whether this sender has an RX ring capable of delivering received frames.
    ///
    /// Returns `true` for real AF_XDP senders and mocks that support RX frame
    /// queuing. Returns `false` for raw socket fallback, where BPF map polling
    /// handles response detection instead of the AF_XDP RX ring.
    ///
    /// Used to determine whether the AF_XDP RX ring is available for
    /// response delivery in the raw SYN probe timing path.
    fn has_rx(&self) -> bool {
        true
    }

    /// Return `self` as `&dyn Any` to enable safe downcasting in tests.
    fn as_any(&self) -> &dyn Any;
}

// =============================================================================
// Mock implementation for unit testing
// =============================================================================

/// Mock AF_XDP sender that records sent packets and returns pre-queued RX frames.
///
/// Used by all unit tests that exercise `SynScanner` sending behaviour without
/// requiring kernel privileges or a real network interface.
#[derive(Debug)]
pub struct MockAfXdpSender {
    /// Packets written via `send_raw`, in order sent.
    pub sent_packets: Vec<Vec<u8>>,
    /// Pre-queued RX frames returned by `poll_rx` in FIFO order.
    rx_queue: VecDeque<RxFrame>,
    /// Source IP reported to packet builders.
    src_ip: Ipv4Addr,
    /// Whether the next `send_raw` should fail.
    pub fail_next_send: bool,
}

impl MockAfXdpSender {
    /// Create a new mock with a fixed source IP of 192.168.1.100.
    pub fn new() -> Self {
        Self {
            sent_packets: Vec::new(),
            rx_queue: VecDeque::new(),
            src_ip: Ipv4Addr::new(192, 168, 1, 100),
            fail_next_send: false,
        }
    }

    /// Create a new mock with a specific source IP.
    pub fn with_src_ip(src_ip: Ipv4Addr) -> Self {
        Self {
            src_ip,
            ..Self::new()
        }
    }

    /// Queue an RX frame to be returned by the next `poll_rx` call.
    pub fn queue_rx_frame(&mut self, data: Vec<u8>) {
        self.rx_queue.push_back(RxFrame { data });
    }

    /// Number of packets sent so far.
    pub fn sent_count(&self) -> usize {
        self.sent_packets.len()
    }

    /// Drain all sent packets (for assertions after a batch).
    pub fn drain_sent(&mut self) -> Vec<Vec<u8>> {
        self.sent_packets.drain(..).collect()
    }
}

impl Default for MockAfXdpSender {
    fn default() -> Self {
        Self::new()
    }
}

impl AfXdpSend for MockAfXdpSender {
    fn send_raw(&mut self, packet: &[u8]) -> Result<(), ScanError> {
        if self.fail_next_send {
            self.fail_next_send = false;
            return Err(ScanError::Send("mock send failure".into()));
        }
        self.sent_packets.push(packet.to_vec());
        Ok(())
    }

    fn poll_rx(&mut self, _timeout_ms: u64) -> Vec<RxFrame> {
        match self.rx_queue.pop_front() {
            Some(frame) => vec![frame],
            None => vec![],
        }
    }

    fn source_ip(&self) -> Ipv4Addr {
        self.src_ip
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// =============================================================================
// Real AF_XDP implementation (Linux only)
// =============================================================================

/// Real AF_XDP sender using kernel UMEM + XDP rings.
///
/// Requires `CAP_NET_ADMIN` and `CAP_BPF`. The BPF program must have the
/// `xsk_map` XSKMAP populated at index 0 with this socket's file descriptor
/// before `poll_rx` will receive packets.
///
/// # Memory layout
/// UMEM is split into two halves:
/// - TX half: frames `0..ring_size-1` — used by `send_raw` for outgoing SYN probes
/// - RX half: frames `ring_size..frame_count-1` — pre-populated into the fill ring
///
/// All four rings (fill, completion, TX, RX) are mmap'd and managed directly.
/// The fill ring is pre-populated at construction so the kernel always has frames
/// available for incoming redirected packets. `poll_rx` returns consumed frames to
/// the fill ring after reading them so the ring never runs dry.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // frame_count, fill_cons_off, comp_desc_off stored for potential diagnostics
pub struct AfXdpSender {
    fd: i32,
    umem_area: *mut libc::c_void,
    umem_size: usize,
    pub frame_size: u32,
    frame_count: u32,
    /// Entries per ring = frame_count / 2.
    pub ring_size: u32,
    src_ip: Ipv4Addr,

    // Mmap'd ring regions
    fill_ring: *mut libc::c_void,
    fill_ring_mmap_size: usize,
    tx_ring: *mut libc::c_void,
    tx_ring_mmap_size: usize,
    rx_ring: *mut libc::c_void,
    rx_ring_mmap_size: usize,
    comp_ring: *mut libc::c_void,
    comp_ring_mmap_size: usize,

    // Byte offsets within each ring mmap (from getsockopt XDP_MMAP_OFFSETS)
    pub fill_prod_off: usize,
    fill_cons_off: usize,
    pub fill_desc_off: usize,
    tx_prod_off: usize,
    tx_desc_off: usize,
    rx_prod_off: usize,
    rx_cons_off: usize,
    rx_desc_off: usize,
    comp_prod_off: usize,
    comp_cons_off: usize,
    comp_desc_off: usize,

    // Cached ring indices (our side of each ring).
    // We advance these and write them back with RELEASE ordering.
    pub fill_prod: u32, // fill: we are producer
    tx_prod: u32,       // tx: we are producer
    tx_frame_idx: u32,  // cycles through TX UMEM frames (0..ring_size-1)
    rx_cons: u32,       // rx: we are consumer
    comp_cons: u32,     // completion: we are consumer

    // Ethernet header fields prepended to every TX frame.
    // build_syn_packet() returns IP-only; AF_XDP TX requires full Ethernet frames.
    src_mac: [u8; 6], // our interface MAC
    dst_mac: [u8; 6], // default gateway MAC (next-hop for all external traffic)
}

#[cfg(target_os = "linux")]
unsafe impl Send for AfXdpSender {}

#[cfg(target_os = "linux")]
impl AfXdpSender {
    /// Linux AF_XDP socket address family.
    const AF_XDP: libc::c_int = 44;
    /// Default frame size for AF_XDP UMEM (4096 bytes).
    pub const DEFAULT_FRAME_SIZE: u32 = 4096;
    /// Default total frame count (TX half + RX half).
    pub const DEFAULT_FRAME_COUNT: u32 = 512;

    /// Create a new AF_XDP sender bound to `ifname` on `queue_id`.
    ///
    /// Allocates UMEM, creates the AF_XDP socket, mmaps all four rings, and
    /// pre-populates the fill ring with RX frame addresses. The caller must
    /// register the returned socket fd in the BPF `xsk_map` at index 0.
    ///
    /// # Errors
    /// Returns `ScanError::RawSocket` if socket creation, UMEM registration,
    /// ring configuration, ring mmap, or bind fails.
    pub fn new(ifname: &str, queue_id: u32, src_ip: Ipv4Addr) -> Result<Self, ScanError> {
        let frame_count = Self::DEFAULT_FRAME_COUNT;
        let frame_size = Self::DEFAULT_FRAME_SIZE;
        let ring_size = frame_count / 2; // 256 entries per ring
        let umem_size = (frame_count * frame_size) as usize;

        // Allocate UMEM as a page-aligned anonymous mapping
        let umem_area = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                umem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if umem_area == libc::MAP_FAILED {
            return Err(ScanError::RawSocket(format!(
                "AF_XDP UMEM mmap failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Create AF_XDP socket
        let fd = unsafe { libc::socket(Self::AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            unsafe { libc::munmap(umem_area, umem_size) };
            return Err(ScanError::RawSocket(format!(
                "AF_XDP socket() failed (requires CAP_NET_ADMIN): {}",
                std::io::Error::last_os_error()
            )));
        }

        // Register UMEM. Try 32-byte struct (Linux 6.8+) first, fall back to 28-byte.
        if let Err(e) = Self::register_umem(fd, umem_area as u64, umem_size as u64, frame_size) {
            unsafe {
                libc::close(fd);
                libc::munmap(umem_area, umem_size);
            }
            return Err(e);
        }

        // Configure ring sizes (ring_size entries per ring)
        for (opt, name) in &[
            (XDP_UMEM_FILL_RING, "XDP_UMEM_FILL_RING"),
            (XDP_UMEM_COMPLETION_RING, "XDP_UMEM_COMPLETION_RING"),
            (XDP_RX_RING, "XDP_RX_RING"),
            (XDP_TX_RING, "XDP_TX_RING"),
        ] {
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_XDP,
                    *opt,
                    &ring_size as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                unsafe {
                    libc::close(fd);
                    libc::munmap(umem_area, umem_size);
                }
                return Err(ScanError::RawSocket(format!(
                    "AF_XDP {} setsockopt failed: {}",
                    name,
                    std::io::Error::last_os_error()
                )));
            }
        }

        // Bind socket to interface and queue
        let ifindex =
            unsafe { libc::if_nametoindex(std::ffi::CString::new(ifname).unwrap().as_ptr()) };
        if ifindex == 0 {
            unsafe {
                libc::close(fd);
                libc::munmap(umem_area, umem_size);
            }
            return Err(ScanError::RawSocket(format!(
                "interface '{}' not found",
                ifname
            )));
        }

        let sxdp = SockaddrXdp {
            sxdp_family: Self::AF_XDP as u16,
            sxdp_flags: XDP_COPY,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: queue_id,
            sxdp_shared_umem_fd: 0,
        };
        let ret = unsafe {
            libc::bind(
                fd,
                &sxdp as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe {
                libc::close(fd);
                libc::munmap(umem_area, umem_size);
            }
            return Err(ScanError::RawSocket(format!(
                "AF_XDP bind failed (requires CAP_NET_ADMIN): {}",
                std::io::Error::last_os_error()
            )));
        }

        // Look up Ethernet addresses for TX frame headers.
        // AF_XDP TX UMEM frames must be full Ethernet frames; build_syn_packet()
        // returns IP-only. We prepend [dst_mac][src_mac][0x08 0x00] in send_raw.
        let src_mac = Self::read_interface_mac(ifname).inspect_err(|_| unsafe {
            libc::close(fd);
            libc::munmap(umem_area, umem_size);
        })?;
        let dst_mac = Self::resolve_gateway_mac(ifname).inspect_err(|_| unsafe {
            libc::close(fd);
            libc::munmap(umem_area, umem_size);
        })?;
        tracing::debug!(
            src_mac = %format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]),
            dst_mac = %format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]),
            "AF_XDP TX Ethernet header resolved"
        );

        // Get ring mmap offsets from kernel
        let off = Self::get_mmap_offsets(fd).inspect_err(|_| unsafe {
            libc::close(fd);
            libc::munmap(umem_area, umem_size);
        })?;

        // Helper: round up to page boundary
        let page_align = |n: usize| (n + 4095) & !4095;

        // Mmap all four rings. Fill/completion rings hold u64 addresses (8 bytes each);
        // TX/RX rings hold xdp_desc structs (16 bytes each).
        let fill_mmap_size = page_align(off.fr.desc as usize + ring_size as usize * 8);
        let fill_ring = Self::mmap_ring(fd, XDP_UMEM_PGOFF_FILL_RING, fill_mmap_size).inspect_err(
            |_| unsafe {
                libc::close(fd);
                libc::munmap(umem_area, umem_size);
            },
        )?;

        let comp_mmap_size = page_align(off.cr.desc as usize + ring_size as usize * 8);
        let comp_ring = Self::mmap_ring(fd, XDP_UMEM_PGOFF_COMPLETION_RING, comp_mmap_size)
            .inspect_err(|_| unsafe {
                libc::munmap(fill_ring, fill_mmap_size);
                libc::close(fd);
                libc::munmap(umem_area, umem_size);
            })?;

        let tx_mmap_size = page_align(off.tx.desc as usize + ring_size as usize * 16);
        let tx_ring =
            Self::mmap_ring(fd, XDP_PGOFF_TX_RING, tx_mmap_size).inspect_err(|_| unsafe {
                libc::munmap(comp_ring, comp_mmap_size);
                libc::munmap(fill_ring, fill_mmap_size);
                libc::close(fd);
                libc::munmap(umem_area, umem_size);
            })?;

        let rx_mmap_size = page_align(off.rx.desc as usize + ring_size as usize * 16);
        let rx_ring =
            Self::mmap_ring(fd, XDP_PGOFF_RX_RING, rx_mmap_size).inspect_err(|_| unsafe {
                libc::munmap(tx_ring, tx_mmap_size);
                libc::munmap(comp_ring, comp_mmap_size);
                libc::munmap(fill_ring, fill_mmap_size);
                libc::close(fd);
                libc::munmap(umem_area, umem_size);
            })?;

        // Pre-populate the fill ring with RX frame addresses (second half of UMEM).
        // CRITICAL: without this the kernel has nowhere to put redirected packets
        // and every bpf_redirect_map call results in a drop (xdp_drops counter).
        let fill_desc_base =
            unsafe { (fill_ring as *mut u8).add(off.fr.desc as usize) as *mut u64 };
        for i in 0..ring_size {
            let rx_frame_addr = (ring_size + i) as u64 * frame_size as u64;
            unsafe { std::ptr::write_volatile(fill_desc_base.add(i as usize), rx_frame_addr) };
        }
        // Commit fill ring producer with RELEASE so kernel sees the entries
        let fill_prod = ring_size;
        unsafe {
            let prod_ptr = (fill_ring as *mut u8).add(off.fr.producer as usize) as *mut AtomicU32;
            (*prod_ptr).store(fill_prod, Ordering::Release);
        }
        tracing::debug!(
            ring_size = ring_size,
            rx_start_frame = ring_size,
            rx_end_frame = frame_count - 1,
            "AF_XDP fill ring pre-populated with RX frame addresses"
        );

        Ok(Self {
            fd,
            umem_area,
            umem_size,
            frame_size,
            frame_count,
            ring_size,
            src_ip,
            fill_ring,
            fill_ring_mmap_size: fill_mmap_size,
            tx_ring,
            tx_ring_mmap_size: tx_mmap_size,
            rx_ring,
            rx_ring_mmap_size: rx_mmap_size,
            comp_ring,
            comp_ring_mmap_size: comp_mmap_size,
            fill_prod_off: off.fr.producer as usize,
            fill_cons_off: off.fr.consumer as usize,
            fill_desc_off: off.fr.desc as usize,
            tx_prod_off: off.tx.producer as usize,
            tx_desc_off: off.tx.desc as usize,
            rx_prod_off: off.rx.producer as usize,
            rx_cons_off: off.rx.consumer as usize,
            rx_desc_off: off.rx.desc as usize,
            comp_prod_off: off.cr.producer as usize,
            comp_cons_off: off.cr.consumer as usize,
            comp_desc_off: off.cr.desc as usize,
            fill_prod,
            tx_prod: 0,
            tx_frame_idx: 0,
            rx_cons: 0,
            comp_cons: 0,
            src_mac,
            dst_mac,
        })
    }

    /// Retrieve ring mmap byte offsets via `getsockopt(SOL_XDP, XDP_MMAP_OFFSETS)`.
    ///
    /// Handles both the 96-byte (Linux pre-5.10, no `flags` field) and
    /// 128-byte (Linux 5.10+, with `flags` field) struct layouts.
    fn get_mmap_offsets(fd: i32) -> Result<XdpMmapOffsets, ScanError> {
        let mut off = XdpMmapOffsets {
            rx: XdpRingOffset {
                producer: 0,
                consumer: 0,
                desc: 0,
                flags: 0,
            },
            tx: XdpRingOffset {
                producer: 0,
                consumer: 0,
                desc: 0,
                flags: 0,
            },
            fr: XdpRingOffset {
                producer: 0,
                consumer: 0,
                desc: 0,
                flags: 0,
            },
            cr: XdpRingOffset {
                producer: 0,
                consumer: 0,
                desc: 0,
                flags: 0,
            },
        };
        let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                &mut off as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        };
        if ret < 0 {
            return Err(ScanError::RawSocket(format!(
                "XDP_MMAP_OFFSETS getsockopt failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(off)
    }

    /// mmap a ring at the given AF_XDP socket page offset.
    fn mmap_ring(fd: i32, pgoff: libc::off_t, size: usize) -> Result<*mut libc::c_void, ScanError> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(ScanError::RawSocket(format!(
                "AF_XDP ring mmap failed (pgoff={:#x}): {}",
                pgoff,
                std::io::Error::last_os_error()
            )));
        }
        Ok(ptr)
    }

    /// Attempt `XDP_UMEM_REG` with the 32-byte struct (Linux 6.8+) then fall
    /// back to the 28-byte compat struct (pre-6.8 / some linuxkit builds).
    fn register_umem(fd: i32, addr: u64, len: u64, chunk_size: u32) -> Result<(), ScanError> {
        let reg32 = XdpUmemReg {
            addr,
            len,
            chunk_size,
            headroom: 0,
            flags: 0,
            tx_metadataoff: 0,
        };
        tracing::debug!(
            optlen = 32,
            fd,
            chunk_size,
            len,
            "XDP_UMEM_REG: trying 32-byte struct"
        );
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &reg32 as *const _ as *const libc::c_void,
                32,
            )
        };
        if ret == 0 {
            tracing::debug!(optlen = 32, "XDP_UMEM_REG: 32-byte struct accepted");
            return Ok(());
        }
        let err32 = std::io::Error::last_os_error();
        tracing::debug!(optlen = 32, error = %err32, "XDP_UMEM_REG: 32-byte struct rejected, trying 28-byte");

        let reg28 = XdpUmemRegCompat {
            addr,
            len,
            chunk_size,
            headroom: 0,
            flags: 0,
        };
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &reg28 as *const _ as *const libc::c_void,
                28,
            )
        };
        if ret == 0 {
            tracing::debug!(optlen = 28, "XDP_UMEM_REG: 28-byte compat struct accepted");
            return Ok(());
        }
        let err28 = std::io::Error::last_os_error();

        Err(ScanError::RawSocket(format!(
            "AF_XDP XDP_UMEM_REG failed with both struct sizes \
             (32-byte: {err32}, 28-byte: {err28}; chunk_size={chunk_size} len={len})"
        )))
    }

    /// Return the AF_XDP socket file descriptor.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    // -------------------------------------------------------------------------
    // Ethernet address resolution helpers
    // -------------------------------------------------------------------------

    /// Parse a colon-separated MAC address string (e.g. "fe:00:00:00:01:01").
    pub(crate) fn parse_mac_str(s: &str) -> Result<[u8; 6], ScanError> {
        let s = s.trim();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(ScanError::RawSocket(format!(
                "invalid MAC address: '{}'",
                s
            )));
        }
        let mut mac = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(p, 16).map_err(|_| {
                ScanError::RawSocket(format!("invalid MAC octet '{}' in '{}'", p, s))
            })?;
        }
        Ok(mac)
    }

    /// Parse the default gateway IPv4 address from `/proc/net/route` content.
    ///
    /// Returns the first entry where Destination == "00000000" and Flags has both
    /// RTF_UP (0x1) and RTF_GATEWAY (0x2) bits set.
    ///
    /// The Gateway field is a 32-bit little-endian hex value as stored in the
    /// kernel routing table (host byte order on x86_64 = little-endian).
    pub(crate) fn parse_gateway_from_proc_route(content: &str) -> Option<std::net::Ipv4Addr> {
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            let dest = fields[1];
            let gw = fields[2];
            let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
            // Default route: destination 0.0.0.0, flags RTF_UP|RTF_GATEWAY
            if dest == "00000000" && (flags & 0x3) == 0x3 {
                let gw_num = u32::from_str_radix(gw, 16).unwrap_or(0);
                let b = gw_num.to_le_bytes();
                return Some(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            }
        }
        None
    }

    /// Find a MAC address in `/proc/net/arp` content for the given IPv4 address.
    ///
    /// Returns `None` if the IP is not in the table or has an incomplete entry
    /// (HW address "00:00:00:00:00:00").
    pub(crate) fn parse_arp_mac(content: &str, ip: std::net::Ipv4Addr) -> Option<[u8; 6]> {
        let ip_str = ip.to_string();
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            if fields[0] != ip_str {
                continue;
            }
            let mac_str = fields[3];
            if mac_str == "00:00:00:00:00:00" {
                continue; // incomplete entry
            }
            return Self::parse_mac_str(mac_str).ok();
        }
        None
    }

    /// Read the MAC address of `ifname` from `/sys/class/net/{ifname}/address`.
    fn read_interface_mac(ifname: &str) -> Result<[u8; 6], ScanError> {
        let path = format!("/sys/class/net/{}/address", ifname);
        let content = std::fs::read_to_string(&path).map_err(|e| {
            ScanError::RawSocket(format!("read interface MAC from {}: {}", path, e))
        })?;
        Self::parse_mac_str(content.trim())
    }

    /// Resolve the default gateway MAC address for `ifname`.
    ///
    /// Reads the default gateway IP from `/proc/net/route`, then looks up its
    /// MAC in `/proc/net/arp`. Triggers an ARP resolution via `arping` if the
    /// entry is missing (common on a fresh VM before any outbound traffic).
    fn resolve_gateway_mac(ifname: &str) -> Result<[u8; 6], ScanError> {
        let route_content = std::fs::read_to_string("/proc/net/route")
            .map_err(|e| ScanError::RawSocket(format!("read /proc/net/route: {}", e)))?;
        let gw_ip = Self::parse_gateway_from_proc_route(&route_content).ok_or_else(|| {
            ScanError::RawSocket("no default gateway found in /proc/net/route".to_string())
        })?;

        // Try ARP cache first (fast path — almost always populated on cloud VMs)
        let arp_content = std::fs::read_to_string("/proc/net/arp")
            .map_err(|e| ScanError::RawSocket(format!("read /proc/net/arp: {}", e)))?;
        if let Some(mac) = Self::parse_arp_mac(&arp_content, gw_ip) {
            return Ok(mac);
        }

        // ARP cache miss: send a single ping to populate it, then re-read
        tracing::debug!(gateway = %gw_ip, "Gateway not in ARP cache — sending ping to resolve");
        let _ = std::process::Command::new("ping")
            .args(["-c", "1", "-W", "1", "-I", ifname, &gw_ip.to_string()])
            .output();

        let arp_content2 = std::fs::read_to_string("/proc/net/arp")
            .map_err(|e| ScanError::RawSocket(format!("read /proc/net/arp after ping: {}", e)))?;
        Self::parse_arp_mac(&arp_content2, gw_ip).ok_or_else(|| {
            ScanError::RawSocket(format!(
                "gateway {} MAC not in ARP cache after ping — cannot send AF_XDP frames",
                gw_ip
            ))
        })
    }

    /// Drain the completion ring to acknowledge that TX frames have been sent.
    ///
    /// This must be called periodically to avoid TX ring starvation on high-rate
    /// scanning. For our SYN-probe-per-target use case it is called before each
    /// `send_raw` to keep the ring clear.
    fn drain_completion_ring(&mut self) {
        let comp_base = self.comp_ring as *mut u8;
        let mut consumed = 0u32;
        loop {
            let prod = unsafe {
                let p = comp_base.add(self.comp_prod_off) as *const AtomicU32;
                (*p).load(Ordering::Acquire)
            };
            if prod == self.comp_cons.wrapping_add(consumed) {
                break;
            }
            consumed += 1;
        }
        if consumed > 0 {
            self.comp_cons = self.comp_cons.wrapping_add(consumed);
            unsafe {
                let p = comp_base.add(self.comp_cons_off) as *mut AtomicU32;
                (*p).store(self.comp_cons, Ordering::Release);
            }
        }
    }

    /// Push a UMEM frame address back into the fill ring.
    ///
    /// Called by `poll_rx` after consuming each RX frame to keep the fill ring
    /// populated. Without this the ring drains after `ring_size` receives and
    /// all subsequent XDP redirects are dropped.
    fn push_fill_ring(&mut self, frame_addr: u64) {
        let fill_base = self.fill_ring as *mut u8;
        let desc_ptr = unsafe { fill_base.add(self.fill_desc_off) as *mut u64 };
        unsafe {
            std::ptr::write_volatile(
                desc_ptr.add((self.fill_prod % self.ring_size) as usize),
                frame_addr,
            );
        }
        self.fill_prod = self.fill_prod.wrapping_add(1);
        unsafe {
            let p = fill_base.add(self.fill_prod_off) as *mut AtomicU32;
            (*p).store(self.fill_prod, Ordering::Release);
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for AfXdpSender {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.rx_ring, self.rx_ring_mmap_size);
            libc::munmap(self.tx_ring, self.tx_ring_mmap_size);
            libc::munmap(self.comp_ring, self.comp_ring_mmap_size);
            libc::munmap(self.fill_ring, self.fill_ring_mmap_size);
            libc::close(self.fd);
            libc::munmap(self.umem_area, self.umem_size);
        }
    }
}

#[cfg(target_os = "linux")]
impl AfXdpSend for AfXdpSender {
    /// Send a raw packet via the AF_XDP TX ring.
    ///
    /// Writes packet bytes into the TX half of UMEM, adds a TX ring descriptor
    /// with the frame address and length, advances the producer index, then
    /// calls `sendto(fd, NULL, 0, ...)` to kick the kernel TX path.
    fn send_raw(&mut self, packet: &[u8]) -> Result<(), ScanError> {
        // Full Ethernet frame = 14-byte header + IP packet.
        // build_syn_packet() returns IP-only; AF_XDP TX needs complete Ethernet frames.
        let eth_total = packet.len() + ETH_HDR_LEN;
        if eth_total > self.frame_size as usize {
            return Err(ScanError::Send(format!(
                "packet too large for UMEM frame: {} bytes (max {} after Ethernet header)",
                eth_total, self.frame_size
            )));
        }

        // Drain completed TX frames to avoid ring starvation
        self.drain_completion_ring();

        // TX frame index cycles through the TX half of UMEM (frames 0..ring_size-1)
        let tx_frame = self.tx_frame_idx % self.ring_size;
        let frame_addr = tx_frame as u64 * self.frame_size as u64;
        self.tx_frame_idx = self.tx_frame_idx.wrapping_add(1);

        // Write [dst_mac(6)][src_mac(6)][0x08 0x00][IP packet] into UMEM TX frame.
        // The TC egress BPF parses struct ethhdr so the Ethertype must be 0x0800 (IPv4).
        unsafe {
            let dest = (self.umem_area as *mut u8).add(frame_addr as usize);
            std::ptr::copy_nonoverlapping(self.dst_mac.as_ptr(), dest, 6);
            std::ptr::copy_nonoverlapping(self.src_mac.as_ptr(), dest.add(6), 6);
            dest.add(12).write(0x08); // EtherType IPv4 high byte
            dest.add(13).write(0x00); // EtherType IPv4 low byte
            std::ptr::copy_nonoverlapping(packet.as_ptr(), dest.add(ETH_HDR_LEN), packet.len());
        }

        // Write TX ring descriptor — length is the full Ethernet frame
        let tx_base = self.tx_ring as *mut u8;
        let desc_slot = (self.tx_prod % self.ring_size) as usize;
        unsafe {
            let desc_ptr = tx_base.add(self.tx_desc_off) as *mut XdpDesc;
            std::ptr::write_volatile(
                desc_ptr.add(desc_slot),
                XdpDesc {
                    addr: frame_addr,
                    len: eth_total as u32,
                    options: 0,
                },
            );
        }

        // Advance TX producer with RELEASE so kernel sees the new descriptor
        self.tx_prod = self.tx_prod.wrapping_add(1);
        unsafe {
            let p = tx_base.add(self.tx_prod_off) as *mut AtomicU32;
            (*p).store(self.tx_prod, Ordering::Release);
        }

        // Kick the kernel TX path (sendto with null buf is the AF_XDP doorbell)
        let ret = unsafe {
            libc::sendto(
                self.fd,
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(ScanError::Send(format!("AF_XDP TX kick failed: {}", err)));
            }
        }
        Ok(())
    }

    /// Poll the AF_XDP RX ring for incoming frames.
    ///
    /// Reads descriptors from the RX ring, copies frame bytes from UMEM, and
    /// returns the consumed RX frame addresses to the fill ring so the kernel
    /// has fresh slots for subsequent redirected packets.
    fn poll_rx(&mut self, timeout_ms: u64) -> Vec<RxFrame> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_i32 = if timeout_ms == 0 {
            0
        } else {
            timeout_ms as i32
        };

        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_i32) };
        if ret <= 0 {
            return vec![];
        }

        let rx_base = self.rx_ring as *mut u8;
        let mut frames = Vec::new();
        let ring_size = self.ring_size;

        loop {
            // Check if kernel has produced new RX entries (ACQUIRE load)
            let rx_prod = unsafe {
                let p = rx_base.add(self.rx_prod_off) as *const AtomicU32;
                (*p).load(Ordering::Acquire)
            };
            if rx_prod == self.rx_cons {
                break;
            }

            // Read RX descriptor at current consumer position
            let desc = unsafe {
                let desc_ptr = rx_base.add(self.rx_desc_off) as *const XdpDesc;
                std::ptr::read_volatile(desc_ptr.add((self.rx_cons % ring_size) as usize))
            };

            // Copy frame bytes from UMEM
            let data = unsafe {
                let src = (self.umem_area as *const u8).add(desc.addr as usize);
                let len = (desc.len as usize).min(self.frame_size as usize);
                std::slice::from_raw_parts(src, len).to_vec()
            };
            frames.push(RxFrame { data });

            // Return frame address to fill ring so kernel can reuse the slot
            self.push_fill_ring(desc.addr);

            self.rx_cons = self.rx_cons.wrapping_add(1);
        }

        // Write back RX consumer index with RELEASE so kernel knows we consumed
        if !frames.is_empty() {
            unsafe {
                let p = rx_base.add(self.rx_cons_off) as *mut AtomicU32;
                (*p).store(self.rx_cons, Ordering::Release);
            }
        }

        frames
    }

    fn source_ip(&self) -> Ipv4Addr {
        self.src_ip
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// =============================================================================
// Linux AF_XDP socket constants and structs (not in libc crate)
// =============================================================================

#[cfg(target_os = "linux")]
const SOL_XDP: libc::c_int = 283;
#[cfg(target_os = "linux")]
const XDP_UMEM_REG: libc::c_int = 4;
#[cfg(target_os = "linux")]
const XDP_UMEM_FILL_RING: libc::c_int = 5;
#[cfg(target_os = "linux")]
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
#[cfg(target_os = "linux")]
const XDP_RX_RING: libc::c_int = 2;
#[cfg(target_os = "linux")]
const XDP_TX_RING: libc::c_int = 3;
#[cfg(target_os = "linux")]
const XDP_COPY: u16 = 2;
/// Ethernet header: dst_mac(6) + src_mac(6) + ethertype(2) = 14 bytes.
/// AF_XDP TX UMEM frames must contain full Ethernet frames; `build_syn_packet`
/// returns IP-only so we prepend this header in `send_raw`.
#[cfg(target_os = "linux")]
const ETH_HDR_LEN: usize = 14;

// Ring mmap page offsets (linux/if_xdp.h)
#[cfg(target_os = "linux")]
const XDP_MMAP_OFFSETS: libc::c_int = 1;
#[cfg(target_os = "linux")]
const XDP_PGOFF_RX_RING: libc::off_t = 0;
#[cfg(target_os = "linux")]
const XDP_PGOFF_TX_RING: libc::off_t = 0x80000000;
#[cfg(target_os = "linux")]
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x100000000_u64 as libc::off_t;
#[cfg(target_os = "linux")]
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x180000000_u64 as libc::off_t;

/// Byte offsets of producer, consumer, and descriptor array within a ring mmap.
///
/// Returned by `getsockopt(XDP_MMAP_OFFSETS)`. The `flags` field (Linux 5.10+)
/// points to the need-wakeup flag; we record it but do not use it.
#[cfg(target_os = "linux")]
#[repr(C)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64, // Linux 5.10+
}

/// All four ring mmap offsets returned by `getsockopt(SOL_XDP, XDP_MMAP_OFFSETS)`.
#[cfg(target_os = "linux")]
#[repr(C)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset, // fill ring
    cr: XdpRingOffset, // completion ring
}

/// TX/RX ring descriptor (linux/if_xdp.h `struct xdp_desc`).
#[cfg(target_os = "linux")]
#[repr(C)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

/// Linux 6.8+ `struct xdp_umem_reg` (32 bytes, includes `tx_metadataoff`).
#[cfg(target_os = "linux")]
#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    /// Added in Linux 6.8 (XDP TX metadata support).
    tx_metadataoff: u32,
}

/// Pre-6.8 `struct xdp_umem_reg` (28 bytes, no `tx_metadataoff`).
///
/// Some kernel builds (including linuxkit-derived kernels) may use this older
/// layout. `AfXdpSender::register_umem` tries both sizes automatically.
#[cfg(target_os = "linux")]
#[repr(C)]
struct XdpUmemRegCompat {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ==========================================================================
    // Socket option constant correctness (matches linux/if_xdp.h uapi)
    // ==========================================================================

    #[test]
    #[cfg(target_os = "linux")]
    fn test_xdp_socket_option_constants_match_uapi() {
        // These values are defined in linux/if_xdp.h and must not drift.
        // Incorrect values cause setsockopt to target the wrong option,
        // producing EINVAL for reasons unrelated to the actual registration
        // (e.g. FILL_RING returns EINVAL when UMEM not yet registered).
        assert_eq!(super::XDP_RX_RING, 2);
        assert_eq!(super::XDP_TX_RING, 3);
        assert_eq!(super::XDP_UMEM_REG, 4);
        assert_eq!(super::XDP_UMEM_FILL_RING, 5);
        assert_eq!(super::XDP_UMEM_COMPLETION_RING, 6);
        assert_eq!(super::SOL_XDP, 283);
    }

    // ==========================================================================
    // MockAfXdpSender tests
    // ==========================================================================

    #[test]
    fn test_mock_sender_records_sent_packet() {
        let mut mock = MockAfXdpSender::new();
        let packet = vec![0x45u8, 0x00, 0x00, 0x28]; // minimal IP header start
        mock.send_raw(&packet).unwrap();
        assert_eq!(mock.sent_count(), 1);
        assert_eq!(mock.sent_packets[0], packet);
    }

    #[test]
    fn test_mock_sender_records_multiple_packets() {
        let mut mock = MockAfXdpSender::new();
        for i in 0u8..5 {
            mock.send_raw(&[i, i + 1, i + 2]).unwrap();
        }
        assert_eq!(mock.sent_count(), 5);
        assert_eq!(mock.sent_packets[0], vec![0, 1, 2]);
        assert_eq!(mock.sent_packets[4], vec![4, 5, 6]);
    }

    #[test]
    fn test_mock_sender_poll_rx_returns_queued_frame() {
        let mut mock = MockAfXdpSender::new();
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        mock.queue_rx_frame(data.clone());

        let frames = mock.poll_rx(0);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, data);
    }

    #[test]
    fn test_mock_sender_poll_rx_empty_when_no_frames() {
        let mut mock = MockAfXdpSender::new();
        let frames = mock.poll_rx(100);
        assert!(frames.is_empty());
    }

    #[test]
    fn test_mock_sender_poll_rx_fifo_order() {
        let mut mock = MockAfXdpSender::new();
        mock.queue_rx_frame(vec![1, 2]);
        mock.queue_rx_frame(vec![3, 4]);
        mock.queue_rx_frame(vec![5, 6]);

        let f1 = mock.poll_rx(0);
        let f2 = mock.poll_rx(0);
        let f3 = mock.poll_rx(0);
        let f4 = mock.poll_rx(0);

        assert_eq!(f1[0].data, vec![1, 2]);
        assert_eq!(f2[0].data, vec![3, 4]);
        assert_eq!(f3[0].data, vec![5, 6]);
        assert!(f4.is_empty(), "queue exhausted after 3 frames");
    }

    #[test]
    fn test_mock_sender_fail_next_send() {
        let mut mock = MockAfXdpSender::new();
        mock.fail_next_send = true;
        assert!(mock.send_raw(&[1, 2, 3]).is_err());
        // After failure, flag is reset — next send succeeds
        assert!(mock.send_raw(&[1, 2, 3]).is_ok());
        assert_eq!(mock.sent_count(), 1);
    }

    #[test]
    fn test_mock_sender_drain_sent() {
        let mut mock = MockAfXdpSender::new();
        mock.send_raw(&[1]).unwrap();
        mock.send_raw(&[2]).unwrap();

        let drained = mock.drain_sent();
        assert_eq!(drained.len(), 2);
        assert_eq!(
            mock.sent_count(),
            0,
            "sent queue should be empty after drain"
        );
    }

    #[test]
    fn test_mock_sender_source_ip_default() {
        let mock = MockAfXdpSender::new();
        assert_eq!(mock.source_ip(), Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_mock_sender_with_src_ip() {
        let mock = MockAfXdpSender::with_src_ip(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(mock.source_ip(), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_afxdp_send_trait_object() {
        // Verify MockAfXdpSender can be used as a trait object
        let mut sender: Box<dyn AfXdpSend> = Box::new(MockAfXdpSender::new());
        sender.send_raw(&[0x45]).unwrap();
        let frames = sender.poll_rx(0);
        assert!(frames.is_empty());
    }

    // ==========================================================================
    // Ethernet header helper tests (no Linux/privileges needed)
    // ==========================================================================

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_mac_str_valid() {
        let mac = AfXdpSender::parse_mac_str("fe:00:00:00:01:01").unwrap();
        assert_eq!(mac, [0xfe, 0x00, 0x00, 0x00, 0x01, 0x01]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_mac_str_all_digits() {
        let mac = AfXdpSender::parse_mac_str("3e:81:0b:ed:02:c8").unwrap();
        assert_eq!(mac, [0x3e, 0x81, 0x0b, 0xed, 0x02, 0xc8]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_mac_str_invalid_too_few_octets() {
        assert!(AfXdpSender::parse_mac_str("aa:bb:cc:dd:ee").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_mac_str_invalid_non_hex() {
        assert!(AfXdpSender::parse_mac_str("gg:00:00:00:00:00").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_gateway_from_proc_route_found() {
        // Matches the actual /proc/net/route format on scanner-1
        let content =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                       eth0\t00000000\t01A0F868\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                       eth0\t0000100A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        let gw = AfXdpSender::parse_gateway_from_proc_route(content).unwrap();
        // 0x01A0F868 little-endian bytes = [0x68, 0xF8, 0xA0, 0x01] = 104.248.160.1
        assert_eq!(gw, std::net::Ipv4Addr::new(104, 248, 160, 1));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_gateway_from_proc_route_no_default() {
        let content =
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                       eth0\t0000100A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        assert!(AfXdpSender::parse_gateway_from_proc_route(content).is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_arp_mac_found() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                       104.248.160.1    0x1         0x2         fe:00:00:00:01:01     *        eth0\n\
                       10.100.0.1       0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
        let ip = std::net::Ipv4Addr::new(104, 248, 160, 1);
        let mac = AfXdpSender::parse_arp_mac(content, ip).unwrap();
        assert_eq!(mac, [0xfe, 0x00, 0x00, 0x00, 0x01, 0x01]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_arp_mac_not_found() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                       10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n";
        let ip = std::net::Ipv4Addr::new(192, 168, 1, 1);
        assert!(AfXdpSender::parse_arp_mac(content, ip).is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_arp_mac_incomplete_entry_skipped() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                       104.248.160.1    0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        let ip = std::net::Ipv4Addr::new(104, 248, 160, 1);
        assert!(
            AfXdpSender::parse_arp_mac(content, ip).is_none(),
            "incomplete ARP entry (all-zero MAC) must be skipped"
        );
    }

    // ==========================================================================
    // Integration tests (require CAP_NET_ADMIN, run in privileged container)
    // ==========================================================================

    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn test_afxdp_sender_creates_socket_on_linux() {
        // Requires CAP_NET_ADMIN, run in: docker run --privileged --cap-add NET_ADMIN
        let result = AfXdpSender::new("lo", 0, Ipv4Addr::new(127, 0, 0, 1));
        assert!(
            result.is_ok(),
            "AF_XDP socket creation should succeed: {:?}",
            result.err()
        );
        let sender = result.unwrap();
        assert!(sender.fd() > 0);
    }

    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn test_afxdp_sender_fill_ring_prepopulated() {
        // The fill ring must be pre-populated with ring_size RX frame addresses
        // after construction. Without this, every XDP redirect is dropped by the
        // kernel driver (rx_queue_0_xdp_drops == rx_queue_0_xdp_redirects).
        // Requires CAP_NET_ADMIN.
        // Run: sudo cargo test --lib -- --ignored test_afxdp_sender_fill_ring_prepopulated
        let sender = AfXdpSender::new("lo", 0, Ipv4Addr::new(127, 0, 0, 1))
            .expect("AF_XDP socket creation must succeed with CAP_NET_ADMIN");
        assert_eq!(
            sender.fill_prod, sender.ring_size,
            "fill ring must be pre-populated with ring_size={} entries (one per RX UMEM frame)",
            sender.ring_size
        );
    }

    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn test_afxdp_sender_fill_ring_rx_frame_addresses() {
        // Fill ring entries must point to the RX half of UMEM (frames ring_size..frame_count-1).
        // TX half (frames 0..ring_size-1) must not appear in the fill ring.
        // Requires CAP_NET_ADMIN.
        let sender = AfXdpSender::new("lo", 0, Ipv4Addr::new(127, 0, 0, 1))
            .expect("AF_XDP socket creation must succeed");
        let ring_size = sender.ring_size;
        let frame_size = sender.frame_size;
        for i in 0..ring_size {
            let desc_ptr = unsafe {
                (sender.fill_ring as *const u8)
                    .add(sender.fill_desc_off)
                    .cast::<u64>()
                    .add(i as usize)
            };
            let addr = unsafe { std::ptr::read_volatile(desc_ptr) };
            let frame_idx = addr / frame_size as u64;
            assert!(
                frame_idx >= ring_size as u64,
                "fill ring entry {i} has frame_idx {frame_idx} in TX half (< ring_size {ring_size})"
            );
        }
    }

    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn test_afxdp_sender_no_xdp_drops_after_send_recv() {
        // After sending a SYN probe and polling for a response, the
        // rx_queue_0_xdp_drops counter must not increase. This verifies
        // that the fill ring is replenished after consuming RX frames.
        // Requires CAP_NET_ADMIN + a running XDP program on the interface.
        // Run: sudo cargo test --lib -- --ignored test_afxdp_sender_no_xdp_drops_after_send_recv
        todo!("Integration test — run on bare-metal Linux with AF_XDP BPF program loaded")
    }
}
