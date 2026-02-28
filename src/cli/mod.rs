//! CLI entrypoint for limpet.
//!
//! Parses arguments, selects the timing backend via the Engine, runs the scan,
//! and formats output.

pub mod output;

use uuid::Uuid;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::engine::{self, Engine, ScanEngineConfig};
use crate::scanner::stealth::PacingProfile;
use crate::{PortSpec, ScanRequest, TimingRequest};

pub use engine::resolve_target;
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
    /// Network interface for XDP (auto-detect if omitted)
    #[arg(long)]
    pub interface: Option<String>,
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
// Scan engine
// ─────────────────────────────────────────────────────────────────────────────

/// Run a port scan and return the result.
///
/// Creates an Engine, builds a ScanRequest, and delegates to `engine.discover()`.
pub async fn run_scan(
    target: &str,
    port_spec: PortSpec,
    pacing: PacingProfile,
    timeout_ms: u32,
    interface: Option<String>,
) -> Result<ScanResult, String> {
    let engine = Engine::new(ScanEngineConfig {
        interface: interface.clone(),
        passthrough: false,
    });

    let request = ScanRequest {
        request_id: Uuid::new_v4(),
        target: target.to_string(),
        ports: port_spec,
        pacing,
        timeout_ms,
        interface,
        max_ports: None,
    };

    let result = engine.discover(&request).await;
    if let Some(ref e) = result.error {
        Err(e.clone())
    } else {
        Ok(result)
    }
}

use crate::ScanResult;

// ─────────────────────────────────────────────────────────────────────────────
// Timing subcommand
// ─────────────────────────────────────────────────────────────────────────────

/// Run RTT timing for a single port and print results.
///
/// Creates an Engine and delegates to `engine.collect_timing()`.
pub async fn run_time(
    target: &str,
    port: u16,
    samples: u32,
    timeout_ms: u32,
    output: OutputFmt,
    interface: Option<String>,
) -> Result<(), String> {
    let (_, hostname) = resolve_target(target)?;

    let engine = Engine::new(ScanEngineConfig {
        interface,
        passthrough: false,
    });

    let request = TimingRequest {
        request_id: Uuid::new_v4(),
        scan_id: None,
        target_host: target.to_string(),
        target_port: port,
        sample_count: samples,
        timeout_ms,
        banner_timeout_ms: None,
    };

    let result = engine.collect_timing(&request).await;

    match output {
        OutputFmt::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        }
        OutputFmt::Pretty => {
            let target_ip_str = resolve_target(target)
                .map(|(ip, _)| ip.to_string())
                .unwrap_or_else(|_| target.to_string());

            let host_label = hostname
                .map(|h| format!("{h} ({target_ip_str})"))
                .unwrap_or(target_ip_str);

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
