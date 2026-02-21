# limpet

High-precision network scanner with eBPF/XDP kernel-bypass timing — nmap with nanosecond RTT measurement and ML-ready feature extraction.

## Features

- **XDP kernel-bypass scanning** — AF_XDP zero-copy SYN packets bypass iptables RST suppression
- **Nanosecond RTT precision** — BPF ktime_get_ns() timestamps for accurate TCP handshake timing
- **ML-ready feature extraction** — 64-dimensional embedding vectors from timing samples for service fingerprinting
- **MCP server** — native Model Context Protocol support for AI agent integration
- **nmap-style output** — familiar port/state/timing columns with JSON alternative

## Requirements

- Linux 5.8+ (for BPF ring buffers and AF_XDP)
- `CAP_BPF` + `CAP_NET_ADMIN` — run with `sudo` or grant capabilities
- libbpf headers (usually `libbpf-dev` / `libbpf-devel`)
- clang + llvm (for BPF program compilation)

> macOS: the binary compiles but XDP is unavailable. The userspace fallback activates automatically for timing; port scanning requires Linux.

## Install

```bash
# From source
git clone https://github.com/nullrabbit/limpet
cd limpet
cargo build --release
sudo cp target/release/limpet /usr/local/bin/
```

## Usage

### Port scan (default)

```bash
# Scan common ports
sudo limpet 1.2.3.4

# Custom port range
sudo limpet 1.2.3.4 --ports 1-1024

# Specific ports, JSON output
sudo limpet 1.2.3.4 --ports 22,80,443,8080 --output json

# Slow/stealthy scan
sudo limpet 1.2.3.4 --ports 1-65535 --stealth paranoid
```

### RTT timing

```bash
# Measure RTT to a specific port (20 samples)
sudo limpet time 1.2.3.4 --port 443 --samples 20

# JSON timing output
sudo limpet time 1.2.3.4 --port 80 --samples 10 --output json
```

### MCP server (for AI agents)

```bash
# Start MCP server on stdio
sudo limpet --mcp
```

## Output

### Pretty (default)

```
Starting limpet 0.1.0 ( https://github.com/nullrabbit/limpet )
Scan report for 1.2.3.4
Host is up (12.1ms latency). Backend: xdp

PORT      STATE     TIMING    TTL   WIN
22/tcp    open      1.20ms    64    65535
80/tcp    open      0.80ms    64    65535
443/tcp   open      0.90ms    64    65535
8080/tcp  filtered  -         -     -

4 ports scanned in 3.42s (3 open, 1 filtered, 0 closed)
```

### JSON

```json
{
  "request_id": "550e8400-...",
  "target": "1.2.3.4",
  "hostname": null,
  "backend": "xdp",
  "duration_ms": 3420,
  "scanned_at": "2026-01-01T00:00:00Z",
  "ports": [
    { "port": 22, "state": "open", "timing_ns": 1200000, "ttl": 64, "win": 65535 },
    { "port": 80, "state": "open", "timing_ns": 800000,  "ttl": 64, "win": 65535 }
  ]
}
```

## MCP Tools

When running as `limpet --mcp`, three tools are available to MCP clients (Claude Desktop, Claude Code, etc.):

| Tool | Description |
|------|-------------|
| `scan_ports` | Discover open ports via XDP SYN scanning |
| `time_port` | Measure TCP RTT with nanosecond precision |
| `get_timing_features` | Extract 64-dim ML feature vector from timing samples |

### Claude Desktop config

```json
{
  "mcpServers": {
    "limpet": {
      "command": "sudo",
      "args": ["/usr/local/bin/limpet", "--mcp"]
    }
  }
}
```

## Options

```
limpet [OPTIONS] [TARGET]
limpet scan <TARGET> [OPTIONS]
limpet time <TARGET> --port <PORT> [OPTIONS]
limpet --mcp

Options:
  --ports <SPEC>       Port spec: "80", "1-1024", "80,443,8080", "1-65535"  [default: 1-65535]
  --stealth <PROFILE>  aggressive | normal | stealthy | paranoid              [default: normal]
  --timeout <MS>       Per-port response timeout in milliseconds              [default: 2000]
  --output <FMT>       pretty | json                                          [default: pretty]
  --interface <IFACE>  Network interface for XDP (auto-detect if omitted)
  --mcp                Run as MCP server over stdio
  -h, --help
  -V, --version
```

## Stealth profiles

| Profile | Batch size | Inter-packet delay | Use case |
|---------|------------|-------------------|----------|
| `aggressive` | 256 | ~0.5ms | Fast internal network scan |
| `normal` | 64 | ~2ms | Default — balanced speed/noise |
| `stealthy` | 16 | ~10ms | Avoid IDS rate-based detection |
| `paranoid` | 4 | ~50ms | Maximum evasion |

## Architecture

```
limpet
├── src/timing/     — BPF timing backend (XDP ktime, userspace fallback)
├── src/scanner/    — SYN sender, AF_XDP socket, discovery collector
├── src/cli/        — Argument parsing, scan engine wiring, output formatters
├── src/mcp/        — MCP server (rmcp, stdio transport)
└── bpf/            — eBPF C program (timing.bpf.c)
```

The BPF program attaches to TC egress and XDP ingress. TX timestamps are stored in a BPF hash map keyed by `(src_port, dst_port, dst_ip)`. On SYN-ACK receipt, the RTT is computed as `rx_ktime - tx_ktime`.

## License

MIT
