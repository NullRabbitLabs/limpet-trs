//! CLI entrypoint for limpet.
//!
//! Parses arguments, resolves DNS, selects the timing backend, runs the scan,
//! and formats output. On Linux with XDP available, uses kernel-bypass timing.

pub mod output;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::scanner::collector::DiscoveryCollector;
use crate::scanner::stealth::{PacingProfile, StealthProfile};
use crate::scanner::syn_sender::{detect_source_ip, SynScanner};
use crate::timing::collect_timing_samples;
use crate::{PortSpec, ScanResult, ScannedPort, TimingRequest};

pub use output::{format_json, format_pretty};

// ─────────────────────────────────────────────────────────────────────────────
// CLI definition
// ─────────────────────────────────────────────────────────────────────────────

/// Limpet — high-precision network scanner with eBPF/XDP kernel-bypass timing.
#[derive(Parser, Debug)]
#[command(name = "limpet", version, about)]
#[command(
    long_about = "Limpet is a network scanner and RTT timing tool using XDP kernel-bypass \
    for nanosecond-precision TCP handshake timing. Like nmap but with BPF timestamps \
    and ML-ready feature extraction. Requires CAP_BPF + CAP_NET_ADMIN (sudo) on Linux."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Target IP address or hostname (for default scan subcommand)
    pub target: Option<String>,

    /// Port specification: "80", "1-1024", "80,443,8080", "1-65535"
    #[arg(long, default_value = "1-65535")]
    pub ports: Option<String>,

    /// Stealth/pacing profile
    #[arg(long, default_value = "normal", value_enum)]
    pub stealth: Option<StealthArg>,

    /// Per-port response timeout in milliseconds
    #[arg(long, default_value = "2000")]
    pub timeout: Option<u32>,

    /// Output format
    #[arg(long, default_value = "pretty", value_enum)]
    pub output: Option<OutputFmt>,

    /// Network interface for XDP (auto-detect from routing table if omitted)
    #[arg(long)]
    pub interface: Option<String>,
}

/// Subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Port discovery scan (default)
    Scan(ScanArgs),
    /// RTT timing measurement for a single port
    Time(TimeArgs),
}

/// Arguments for the `scan` subcommand.
#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Target IP address or hostname
    pub target: String,
    /// Port specification: "80", "1-1024", "80,443,8080", "1-65535"
    #[arg(long, default_value = "1-65535")]
    pub ports: String,
    /// Stealth/pacing profile
    #[arg(long, default_value = "normal", value_enum)]
    pub stealth: StealthArg,
    /// Per-port response timeout in milliseconds
    #[arg(long, default_value = "2000")]
    pub timeout: u32,
    /// Output format
    #[arg(long, default_value = "pretty", value_enum)]
    pub output: OutputFmt,
    /// Network interface for XDP (auto-detect if omitted)
    #[arg(long)]
    pub interface: Option<String>,
}

/// Arguments for the `time` subcommand.
#[derive(Args, Debug)]
pub struct TimeArgs {
    /// Target IP address or hostname
    pub target: String,
    /// Port to time
    #[arg(long)]
    pub port: u16,
    /// Number of RTT samples to collect
    #[arg(long, default_value = "10")]
    pub samples: u32,
    /// Per-sample timeout in milliseconds
    #[arg(long, default_value = "2000")]
    pub timeout: u32,
    /// Output format
    #[arg(long, default_value = "pretty", value_enum)]
    pub output: OutputFmt,
}

/// Stealth/pacing profile argument.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthArg {
    Aggressive,
    Normal,
    Stealthy,
    Paranoid,
}

impl From<StealthArg> for PacingProfile {
    fn from(s: StealthArg) -> Self {
        match s {
            StealthArg::Aggressive => PacingProfile::Aggressive,
            StealthArg::Normal => PacingProfile::Normal,
            StealthArg::Stealthy => PacingProfile::Stealthy,
            StealthArg::Paranoid => PacingProfile::Paranoid,
        }
    }
}

/// Output format argument.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFmt {
    Pretty,
    Json,
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
// Scan engine
// ─────────────────────────────────────────────────────────────────────────────

/// Run a port scan and return the result.
///
/// Requires Linux with CAP_BPF + CAP_NET_ADMIN (sudo). On macOS or without
/// BPF support, returns an error.
pub async fn run_scan(
    target: &str,
    port_spec: PortSpec,
    pacing: PacingProfile,
    timeout_ms: u32,
    interface: Option<String>,
) -> Result<ScanResult, String> {
    let start = Instant::now();
    let (target_ip, target_hostname) = resolve_target(target)?;
    let request_id = Uuid::new_v4();

    // Initialise XDP/BPF timing backend (Linux only)
    let (backend, bpf_collector) = crate::timing::detect_timing_backend(&interface)
        .map_err(|e| format!("BPF initialisation failed: {e}"))?;

    let backend_str = backend.as_str().to_string();
    let iface = bpf_collector.interface().to_string();
    let bpf = Arc::new(Mutex::new(bpf_collector));

    // Detect source IP
    let src_ip =
        detect_source_ip(target_ip).map_err(|e| format!("source IP detection failed: {e}"))?;

    // Build stealth profile with pacing applied
    let mut stealth = StealthProfile::linux_6x_default();
    pacing.apply_to(&mut stealth);

    let ports = port_spec.expand();
    let batch_size = pacing.batch_size();
    let timeout = Duration::from_millis(timeout_ms as u64);

    // Create AF_XDP sender or fall back to raw socket (Linux only)
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (iface, bpf, src_ip, stealth, ports, batch_size, timeout);
        return Err("XDP scanning requires Linux with CAP_BPF and CAP_NET_ADMIN".to_string());
    }

    #[cfg(target_os = "linux")]
    {
        use crate::scanner::afxdp_sender::AfXdpSend;
        use crate::scanner::hybrid_sender::HybridSender;
        use crate::scanner::raw_socket_sender::RawSocketSender;

        let xdp_sender: Box<dyn AfXdpSend> = match HybridSender::new(&iface, 0, src_ip) {
            Ok(sender) => {
                // Register the AF_XDP socket in the BPF xsk_map
                let bpf_guard = bpf.lock().await;
                if let Err(e) = bpf_guard.register_xsk_fd(sender.fd()) {
                    tracing::warn!(error = %e, "xsk_map registration failed — responses may not be captured");
                }
                drop(bpf_guard);
                Box::new(sender)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "hybrid sender unavailable — falling back to raw socket TX"
                );
                Box::new(
                    RawSocketSender::new(src_ip)
                        .map_err(|e| format!("raw socket fallback failed: {e}"))?,
                )
            }
        };

        let mut scanner = SynScanner::new_with_sender(stealth, xdp_sender);
        let collector = DiscoveryCollector::new(timeout);
        let target_ip_u32 = u32::from_be_bytes(target_ip.octets());

        let mut all_ports: Vec<ScannedPort> = Vec::with_capacity(ports.len());

        // Send all probe batches
        let mut all_probes = Vec::new();
        for batch in ports.chunks(batch_size) {
            let result = scanner
                .send_syn_batch(target_ip, batch)
                .map_err(|e| format!("scan error: {e}"))?;
            all_probes.extend(result.probed_ports);
        }

        // Wait for responses to arrive in the BPF map
        tokio::time::sleep(Duration::from_millis(timeout_ms as u64)).await;

        // Collect all results in one pass
        let bpf_guard = bpf.lock().await;
        let discovery = collector.collect(&all_probes, &*bpf_guard, target_ip_u32);
        drop(bpf_guard);

        for port in discovery.ports {
            all_ports.push(ScannedPort {
                port: port.port,
                state: port.state,
                timing_ns: port.timing_ns,
                response_ttl: port.response_ttl,
                response_win: port.response_win,
            });
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ScanResult {
            request_id,
            target_ip,
            target_hostname,
            ports: all_ports,
            duration_ms,
            backend: backend_str,
            scanned_at: Utc::now(),
            error: None,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Timing subcommand
// ─────────────────────────────────────────────────────────────────────────────

/// Run RTT timing for a single port and print results.
pub async fn run_time(
    target: &str,
    port: u16,
    samples: u32,
    timeout_ms: u32,
    output: OutputFmt,
) -> Result<(), String> {
    let (target_ip, hostname) = resolve_target(target)?;

    let request = TimingRequest {
        request_id: Uuid::new_v4(),
        scan_id: None,
        target_host: target.to_string(),
        target_port: port,
        sample_count: samples,
        timeout_ms,
        banner_timeout_ms: None,
    };

    let result = collect_timing_samples(&request, None).await;

    match output {
        OutputFmt::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        }
        OutputFmt::Pretty => {
            let host_label = hostname
                .map(|h| format!("{h} ({target_ip})"))
                .unwrap_or_else(|| target_ip.to_string());

            println!("Timing report for {host_label} port {port}/tcp");
            if let Some(err) = &result.error {
                println!("Error: {err}");
            } else {
                println!("Backend:   {}", result.precision_class);
                println!("Samples:   {}", result.samples.len());
                println!("Mean RTT:  {:.2}µs", result.stats.mean);
                println!("Std Dev:   {:.2}µs", result.stats.std);
                println!("P50:       {:.2}µs", result.stats.p50);
                println!("P90:       {:.2}µs", result.stats.p90);
            }
        }
    }

    Ok(())
}
