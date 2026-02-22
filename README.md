# limpet

High-precision network scanner with eBPF/XDP kernel-bypass timing. Sends raw TCP SYNs, captures responses at the kernel boundary via BPF maps, and measures round-trip time with nanosecond resolution.

Limpet is not a replacement for nmap's service fingerprinting — it does one thing well: **tell you which ports are open and how long they took to respond**.

```
$ sudo limpet 192.168.1.1
PORT     STATE     RTT
22/tcp   open      1.2ms
80/tcp   open      0.8ms
443/tcp  open      0.9ms
8080/tcp filtered  —
Scanned 1000 ports in 2.1s
```

---

## Features

- **SYN scanner** — raw socket sender, no connection established
- **XDP/BPF timing** — per-packet timestamps from the kernel bypass path; falls back to userspace `gettimeofday` when XDP is unavailable
- **Stealth pacing** — configurable inter-packet delay to avoid triggering rate limits
- **ML-ready output** — timing samples (not just a single RTT), mean/p50/p90 stats, and 64-dim embedding vectors for each port
- **JSON output** — machine-readable results for pipelines
- **MCP server** — exposes scan and timing tools to AI assistants via the Model Context Protocol
- **HTTP server** (`limpet-server`) — REST API for orchestration systems

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Linux kernel ≥ 5.11 | For BPF ring buffers; XDP timing degrades gracefully to userspace on older kernels |
| `NET_RAW` + `NET_ADMIN` capabilities | Required for raw socket SYN scanning |
| `CAP_BPF` + `CAP_SYS_ADMIN` | Required for XDP/BPF timing (not needed for userspace fallback) |
| Bare-metal or KVM VM | AF_XDP requires a real NIC driver; Docker Desktop (macOS/Windows) will fall back to userspace timing |
| Root or `sudo` | Easiest path; or grant caps with `setcap` |

**Does not work on:** macOS, Windows, Docker Desktop (for BPF features — CLI builds but timing falls back to userspace).

---

## Installation

### Build from source

```bash
# BPF build dependencies (Debian/Ubuntu)
sudo apt-get install llvm clang libbpf-dev libelf-dev linux-libc-dev

# Install Rust if needed
curl https://sh.rustup.rs | sh

git clone https://github.com/nullrabbit/limpet
cd limpet
cargo build --release

# Install
sudo cp target/release/limpet /usr/local/bin/
```

### Capabilities (without running as root)

```bash
sudo setcap 'cap_net_raw,cap_net_admin,cap_bpf,cap_sys_admin+eip' /usr/local/bin/limpet
```

---

## CLI Usage

### Quick scan (top 1000 ports)

```bash
sudo limpet 203.0.113.1
```

### Specific ports

```bash
sudo limpet 203.0.113.1 --ports 22,80,443,8080-8090
```

### Full port scan

```bash
sudo limpet 203.0.113.1 --ports 1-65535
```

### JSON output

```bash
sudo limpet scan 203.0.113.1 --ports top-1000 --output json | jq '.port_results[] | select(.state == "Open")'
```

### Stealth scan (slow pacing)

```bash
sudo limpet scan 203.0.113.1 --stealth slowest --ports top-1000
```

Available stealth profiles: `slowest`, `slow`, `normal` (default), `fast`, `turbo`

### TCP RTT timing on a single port

```bash
sudo limpet time 203.0.113.1 --port 443 --samples 10
```

```json
{
  "target_host": "203.0.113.1",
  "target_port": 443,
  "samples": [1210.3, 1184.7, 1241.2, 1193.1, 1216.8, 1201.4, 1228.0, 1210.1, 1184.3, 1241.7],
  "precision_class": "xdp",
  "stats": { "mean": 1211.2, "std": 20.3, "p50": 1210.3, "p90": 1241.2 }
}
```

Samples are in **microseconds**.

### MCP server (for AI assistants)

```bash
limpet --mcp
```

Exposes `scan_ports` and `measure_timing` as MCP tools over stdio. Add to your AI assistant's tool config to run network scans from natural language.

---

## Library Usage

```rust
use limpet::{PortSpec, PortState, TimingRequest};
use limpet::scanner::syn_sender::SynScanner;
use limpet::scanner::collector::DiscoveryCollector;
use limpet::timing::collect_timing_samples;

// Port discovery
let scanner = SynScanner::new("eth0")?;
let collector = DiscoveryCollector::new();
let spec = PortSpec::TopN(1000);
let results = scanner.scan("203.0.113.1".parse()?, spec, collector).await?;

for port in results.iter().filter(|p| p.state == PortState::Open) {
    println!("{}  {:?}  {:.2}ms", port.port, port.state, port.timing_ns as f64 / 1e6);
}

// Single-port RTT timing (10 samples)
let req = TimingRequest {
    target_host: "203.0.113.1".to_string(),
    target_port: 443,
    sample_count: 10,
    timeout_ms: 5000,
    banner_timeout_ms: None,
};
let result = collect_timing_samples(&req).await?;
println!("mean RTT: {:.2}ms", result.stats.mean / 1000.0); // samples are µs
```

---

## HTTP Server (`limpet-server`)

`limpet-server` exposes the scan engine over HTTP for use in distributed scanning pipelines. The orchestrator calls it directly rather than publishing to a message queue.

```bash
# Build
cargo build --release --bin limpet-server

# Run (requires caps or root)
sudo PORT=8888 ./target/release/limpet-server
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8888` | HTTP listen port |
| `LIMPET_INTERFACE` | auto-detect | Network interface for XDP |
| `WORKER_NODE` | hostname | Reported in all responses |
| `RUST_LOG` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

### `GET /v1/health`

```bash
curl http://localhost:8888/v1/health
```
```json
{ "status": "ok", "worker_node": "scanner-1", "source_ip": "10.0.1.5" }
```

### `POST /v1/discovery`

```bash
curl -X POST http://localhost:8888/v1/discovery \
  -H 'Content-Type: application/json' \
  -d '{
    "request_id": "req-001",
    "target_ip": "203.0.113.1",
    "ports": { "type": "top-n", "value": 1000 },
    "timeout_ms": 30000
  }'
```

```json
{
  "request_id": "req-001",
  "target_ip": "203.0.113.1",
  "ports_scanned": 1000,
  "port_results": [
    { "port": 22,  "state": "Open",   "timing_ns": 1204000 },
    { "port": 80,  "state": "Open",   "timing_ns":  823000 },
    { "port": 443, "state": "Open",   "timing_ns":  901000 }
  ],
  "actual_duration_ms": 2140,
  "scanner_backend": "xdp",
  "source_ip": "10.0.1.5",
  "worker_node": "scanner-1"
}
```

### `POST /v1/timing`

```bash
curl -X POST http://localhost:8888/v1/timing \
  -H 'Content-Type: application/json' \
  -d '{
    "request_id": "timing-001",
    "target_host": "203.0.113.1",
    "target_port": 22,
    "sample_count": 5,
    "timeout_ms": 10000
  }'
```

```json
{
  "request_id": "timing-001",
  "target_host": "203.0.113.1",
  "target_port": 22,
  "samples": [1204.3, 1198.7, 1211.2, 1203.1, 1206.8],
  "precision_class": "xdp",
  "stats": { "mean": 1204.8, "std": 4.3, "p50": 1204.3, "p90": 1211.2 },
  "banner": "U1NILTIuMC1PcGVuU1NIXzguOQ==",
  "worker_node": "scanner-1"
}
```

`banner` is base64-encoded raw bytes from the first packet sent by the remote host. Samples are in **microseconds**.

---

## Limitations

**Platform**
- Linux only. The BPF/XDP path requires kernel ≥ 5.11 for ring buffers. Older kernels fall back to userspace timing automatically.
- AF_XDP requires a NIC driver with XDP support. Virtio-net (KVM/QEMU) works. VMware vmxnet3 and some cloud hypervisor NICs do not.
- Docker Desktop on macOS/Windows: the CLI builds and runs but the BPF programs cannot load — timing falls back to userspace.

**Scanning**
- **No service detection** — limpet identifies open ports and collects RTT samples. The `banner` field contains raw bytes from the server's first response packet, but there is no protocol parsing.
- **TCP only** — no UDP scanning.
- **IPv4 only** — the raw socket sender does not support IPv6.
- Large port ranges at `turbo` pacing will generate significant traffic and may trigger firewall rate limits or IDS alerts. Use `--stealth slowest` for quiet scans.
- A `filtered` result means no response was received within the timeout — the port could be firewalled, rate-limited, or the host could be down.

**Timing precision**
- XDP timestamps are recorded at NIC receive time, not in application code. This gives you real wire latency including NIC driver overhead, not software scheduling jitter.
- Userspace fallback (`precision_class: "userspace"`) has ±50–200µs jitter under load — accurate enough for coarse fingerprinting, not for sub-millisecond jitter analysis.
- RTT samples include the full TCP handshake (SYN → SYN-ACK). This is intentional: handshake latency is the fingerprinting signal.

**Permissions**
- Raw socket scanning requires `NET_RAW` and `NET_ADMIN`. BPF timing additionally requires `CAP_BPF` and `CAP_SYS_ADMIN`. There is no unprivileged mode.

**Not a replacement for**
- **nmap** — no OS detection, no script engine, no service version detection
- **masscan** — not optimised for internet-scale scanning; designed for single hosts or small ranges
- **Wireshark / tcpdump** — limpet does not capture arbitrary traffic

---

## Project structure

```
limpet/
├── src/
│   ├── lib.rs              # Public API — PortState, TimingRequest, TimingResult, re-exports
│   ├── main.rs             # CLI binary (limpet)
│   ├── cli/                # Clap argument parsing + scan/time command runners
│   ├── mcp/                # MCP server (scan_ports + measure_timing tools)
│   ├── bin/
│   │   └── server.rs       # limpet-server HTTP binary (Axum)
│   ├── scanner/
│   │   ├── syn_sender.rs   # Raw SYN scanner (AF_PACKET / AF_XDP TX)
│   │   ├── afxdp_sender.rs # AF_XDP zero-copy sender
│   │   ├── collector.rs    # BPF map reader — assembles DiscoveryResult
│   │   ├── stealth.rs      # Pacing profiles (inter-packet delay)
│   │   └── mod.rs
│   └── timing/
│       ├── xdp.rs          # BpfTimingCollector — XDP kernel-bypass timing
│       ├── userspace.rs    # Fallback: connect(2) + gettimeofday timing
│       ├── embeddings.rs   # 64-dim feature vector extraction
│       ├── stats.rs        # Mean / std / percentile helpers
│       └── mod.rs
└── bpf/
    └── timing.bpf.c        # eBPF program — per-packet timestamps into ring buffer
```

---

## Context

Limpet is the open-source scanning component of the [NullRabbit](https://nullrabbit.ai) platform — autonomous defence for validator infrastructure and decentralised networks.

The timing embeddings and ML-ready output from Limpet feed into NullRabbit's proprietary threat analysis and behavioural baseline systems. For the governance framework behind autonomous defensive action, see:

> **On Earned Autonomy: Delegating Network-Lethal Authority to Machines**
> Simon Morley, NullRabbit Labs, January 2026
> [DOI: 10.5281/zenodo.18406828](https://doi.org/10.5281/zenodo.18406828)

---

## License

MIT
