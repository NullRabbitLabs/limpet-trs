//! Limpet — high-precision network scanner and RTT timing tool.
//!
//! Usage:
//!   limpet <TARGET> [--ports <SPEC>] [--stealth <PROFILE>] [--output json|pretty]
//!   limpet scan <TARGET> [OPTIONS]
//!   limpet time <TARGET> --port <PORT> [--samples <N>]

use clap::Parser;
use limpet::cli::{self, Cli, Commands, OutputFmt, StealthArg};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialise logging (RUST_LOG=debug etc.)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan(args)) => {
            run_scan_command(
                &args.target,
                &args.ports,
                args.stealth,
                args.timeout,
                args.output,
                args.interface,
                args.timing_samples,
            )
            .await;
        }
        Some(Commands::Time(args)) => {
            if let Err(e) = cli::run_time(
                &args.target,
                args.port,
                args.samples,
                args.timeout,
                args.output,
                args.interface,
            )
            .await
            {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        None => {
            // Default: scan with top-level args
            let target = match &cli.target {
                Some(t) => t.clone(),
                None => {
                    eprintln!("Error: target argument required (e.g. limpet 1.2.3.4)");
                    eprintln!("Run 'limpet --help' for usage.");
                    std::process::exit(1);
                }
            };
            let ports = cli.ports.unwrap_or_else(|| "1-65535".to_string());
            let stealth = cli.stealth.unwrap_or(StealthArg::Normal);
            let timeout = cli.timeout.unwrap_or(2000);
            let output = cli.output.unwrap_or(OutputFmt::Pretty);

            run_scan_command(&target, &ports, stealth, timeout, output, cli.interface, 0).await;
        }
    }
}

async fn run_scan_command(
    target: &str,
    ports_str: &str,
    stealth: StealthArg,
    timeout: u32,
    output: OutputFmt,
    interface: Option<String>,
    timing_samples: u16,
) {
    let port_spec = match limpet::PortSpec::parse(ports_str) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error parsing port spec '{ports_str}': {e}");
            std::process::exit(1);
        }
    };

    let pacing: limpet::scanner::stealth::PacingProfile = stealth.into();

    match cli::run_scan(target, port_spec, pacing, timeout, interface, timing_samples).await {
        Ok((result, timing_results)) => match output {
            OutputFmt::Pretty => {
                print!("{}", cli::format_pretty(&result, target));
                if !timing_results.is_empty() {
                    println!("\nTiming profiles ({} ports):", timing_results.len());
                    for tr in &timing_results {
                        let emb = if tr.embedding.is_some() { "64-dim" } else { "none" };
                        println!(
                            "  port {}: {} samples, mean={:.2}µs, embedding={}",
                            tr.target_port,
                            tr.samples.len(),
                            tr.stats.mean,
                            emb,
                        );
                    }
                }
            }
            OutputFmt::Json => {
                let out = serde_json::json!({
                    "scan": result,
                    "timing": timing_results,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            }
        },
        Err(e) => {
            eprintln!("Scan failed: {e}");
            std::process::exit(1);
        }
    }
}
