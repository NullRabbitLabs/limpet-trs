//! XDP-native port discovery scanner.
//!
//! Replaces nmap for port discovery with raw SYN packets that are
//! indistinguishable from normal TCP connections. Uses XDP/BPF for
//! response capture and classification, and AF_XDP for kernel-level
//! packet send/receive (eliminating iptables RST suppression).

pub mod afxdp_sender;
pub mod collector;
#[cfg(target_os = "linux")]
pub mod raw_socket_sender;
pub mod stealth;
pub mod syn_sender;

pub use afxdp_sender::{AfXdpSend, MockAfXdpSender, RxFrame};
pub use collector::DiscoveryCollector;
#[cfg(target_os = "linux")]
pub use raw_socket_sender::RawSocketSender;
pub use stealth::{PacingProfile, StealthProfile};
pub use syn_sender::SynScanner;
