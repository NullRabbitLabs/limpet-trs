// SPDX-License-Identifier: MIT
// Limpet Timing BPF Program
//
// Two-program design for TCP handshake timing + port discovery:
// - TC egress: timestamps outgoing SYN packets
// - XDP ingress: timestamps incoming SYN-ACK, RST, and ICMP unreachable packets,
//               then redirects timestamped packets to our AF_XDP socket via XSKMAP
//
// Safety guarantees (enforced by static analysis):
// - XDP returns XDP_PASS on non-matching packets (never XDP_DROP, XDP_ABORTED, XDP_TX)
// - Timestamped packets are redirected via bpf_redirect_map(&xsk_map, 0, XDP_PASS):
//   falls back to XDP_PASS if socket not registered — safe at startup
//   XSKMAP redirect is safe: directs packets only to our own process's AF_XDP socket
// - TC always returns TC_ACT_OK (never TC_ACT_SHOT, TC_ACT_STOLEN)
// - Uses BPF_MAP_TYPE_LRU_HASH for bounded memory
// - No ringbuf/perf_event output (no per-packet events)
// - O(1) per-packet work

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

// ICMP header defined inline to avoid transitive sys/socket.h dependency
// from linux/icmp.h -> linux/if.h (breaks BPF clang builds on Alpine).
// Standard ICMP header: 8 bytes total.
struct icmphdr {
    __u8  type;
    __u8  code;
    __u16 checksum;
    __u32 un;      // union (echo/gateway/frag) — unused, we only need type
};
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map key structure - 8 bytes total
// Layout: src_port(2) + dst_port(2) + dst_ip(4) = 8 bytes
// src_port first for fast concurrent scan disambiguation (unique per probe)
struct timing_key {
    __u16 src_port;   // Our ephemeral port (unique per probe) — first for lookups
    __u16 dst_port;   // Destination port (host byte order)
    __u32 dst_ip;     // Destination IP (network byte order)
};

// Timing value structure - 24 bytes
// Layout: syn_ts_ns(8) + response_ts_ns(8) + flags(4) + port_state(1) + response_ttl(1) + response_win(2) = 24 bytes
//
// flags layout:
//   bits 0-3: syn(0) / synack(1) / rst(2) / icmp(3)
//   bits 28-31: version marker (0x1 for v1)
struct timing_value {
    __u64 syn_ts_ns;       // bpf_ktime_get_ns() from TC egress
    __u64 response_ts_ns;  // bpf_ktime_get_ns() from XDP ingress (SYN-ACK/RST/ICMP)
    __u32 flags;           // bit 0: syn, bit 1: synack, bit 2: rst, bit 3: icmp; bits 28-31: version
    __u8  port_state;      // 0=pending, 1=open, 2=closed, 3=unreachable, 4=filtered(userspace)
    __u8  response_ttl;    // IP TTL from response packet
    __u16 response_win;    // TCP window from response (0 for ICMP)
};

// Version marker for v1 entries (set in top nibble of flags)
#define TIMING_VERSION_1 (0x1 << 28)

// Shared timing map between TC and XDP programs
// LRU hash for bounded memory usage
// 16384 entries to support full-range port scans (65535 ports per target)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct timing_key);
    __type(value, struct timing_value);
} timing_map SEC(".maps");

// AF_XDP socket map for redirecting timestamped packets to userspace.
// Entry 0 is populated by userspace after creating the AF_XDP socket.
// XDP programs redirect here via bpf_redirect_map(&xsk_map, 0, XDP_PASS);
// the XDP_PASS fallback is safe at startup (before socket is registered).
// This eliminates iptables RST suppression: SYN-ACKs never reach the kernel
// TCP stack, so no kernel-generated RSTs are emitted.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

// TC egress program: captures outgoing SYN packets
// Records bpf_ktime_get_ns() as syn_ts_ns
SEC("tc")
int tc_timing_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Only process TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // Calculate IP header length (IHL is in 32-bit words)
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return TC_ACT_OK;

    // Parse TCP header with variable IP header length
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Only capture SYN packets (SYN=1, ACK=0)
    if (!tcp->syn || tcp->ack)
        return TC_ACT_OK;

    // Build map key from outgoing packet
    struct timing_key key = {
        .src_port = bpf_ntohs(tcp->source),      // Our ephemeral port
        .dst_port = bpf_ntohs(tcp->dest),         // Target port
        .dst_ip = ip->daddr,                       // Target IP (network byte order)
    };

    // Record SYN timestamp with version marker
    struct timing_value val = {
        .syn_ts_ns = bpf_ktime_get_ns(),
        .response_ts_ns = 0,
        .flags = 1 | TIMING_VERSION_1,   // bit 0: syn_recorded, version 1
        .port_state = 0,                  // pending
        .response_ttl = 0,
        .response_win = 0,
    };

    bpf_map_update_elem(&timing_map, &key, &val, BPF_ANY);

    // Always pass the packet - we never drop or modify
    return TC_ACT_OK;
}

// XDP ingress program: captures incoming SYN-ACK, RST, and ICMP unreachable packets
// Updates existing entries with response timestamps and port state
SEC("xdp")
int xdp_timing_ingress(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Calculate IP header length
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    // Branch: TCP responses (SYN-ACK or RST)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        // Reconstruct key from incoming packet
        // For ingress: source is the remote server, destination is us
        struct timing_key key = {
            .src_port = bpf_ntohs(tcp->dest),     // Our port (original source)
            .dst_port = bpf_ntohs(tcp->source),   // Remote port (original destination)
            .dst_ip = ip->saddr,                   // Remote IP (original destination, network order)
        };

        // SYN-ACK: port is open
        if (tcp->syn && tcp->ack) {
            struct timing_value *val = bpf_map_lookup_elem(&timing_map, &key);
            if (val) {
                // Normal path: TC recorded the SYN, update with response
                val->response_ts_ns = bpf_ktime_get_ns();
                val->flags |= (2 | TIMING_VERSION_1);   // bit 1: synack, version 1
                val->port_state = 1;                      // open
                val->response_ttl = ip->ttl;
                val->response_win = bpf_ntohs(tcp->window);
            } else {
                // AF_XDP path: TC didn't see the SYN, create response-only entry
                struct timing_value new_val = {
                    .syn_ts_ns = 0,
                    .response_ts_ns = bpf_ktime_get_ns(),
                    .flags = 2 | TIMING_VERSION_1,        // synack only, version 1
                    .port_state = 1,                       // open
                    .response_ttl = ip->ttl,
                    .response_win = bpf_ntohs(tcp->window),
                };
                bpf_map_update_elem(&timing_map, &key, &new_val, BPF_NOEXIST);
            }
            // Redirect to our AF_XDP socket so the kernel TCP stack never sees
            // this SYN-ACK — prevents kernel from sending an RST (no socket owns it).
            // Falls back to XDP_PASS if socket not yet registered (safe at startup).
            return bpf_redirect_map(&xsk_map, 0, XDP_PASS);
        }

        // RST: port is closed
        if (tcp->rst) {
            struct timing_value *val = bpf_map_lookup_elem(&timing_map, &key);
            if (val) {
                val->response_ts_ns = bpf_ktime_get_ns();
                val->flags |= (4 | TIMING_VERSION_1);   // bit 2: rst, version 1
                val->port_state = 2;                      // closed
                val->response_ttl = ip->ttl;
                val->response_win = bpf_ntohs(tcp->window);
            } else {
                struct timing_value new_val = {
                    .syn_ts_ns = 0,
                    .response_ts_ns = bpf_ktime_get_ns(),
                    .flags = 4 | TIMING_VERSION_1,        // rst only, version 1
                    .port_state = 2,                       // closed
                    .response_ttl = ip->ttl,
                    .response_win = bpf_ntohs(tcp->window),
                };
                bpf_map_update_elem(&timing_map, &key, &new_val, BPF_NOEXIST);
            }
            // Redirect RST to AF_XDP socket to avoid RST echo loops
            return bpf_redirect_map(&xsk_map, 0, XDP_PASS);
        }

        return XDP_PASS;
    }

    // Branch: ICMP unreachable (type 3)
    if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)ip + ip_hdr_len;
        if ((void *)(icmp + 1) > data_end)
            return XDP_PASS;

        // Only handle Destination Unreachable (type 3)
        if (icmp->type != 3)
            return XDP_PASS;

        // Parse inner IP header from ICMP payload
        // ICMP error messages include the original IP header + first 8 bytes of transport
        struct iphdr *inner_ip = (void *)(icmp + 1);
        if ((void *)(inner_ip + 1) > data_end)
            return XDP_PASS;

        // Inner packet must be TCP
        if (inner_ip->protocol != IPPROTO_TCP)
            return XDP_PASS;

        __u32 inner_ip_hdr_len = inner_ip->ihl * 4;
        if (inner_ip_hdr_len < sizeof(struct iphdr))
            return XDP_PASS;

        // Parse first 4 bytes of inner TCP header (src_port + dst_port)
        // We only need the port fields, not the full TCP header
        void *inner_tcp_start = (void *)inner_ip + inner_ip_hdr_len;
        if (inner_tcp_start + 4 > data_end)
            return XDP_PASS;

        // Read ports directly (first 4 bytes of TCP header)
        __u16 *inner_ports = inner_tcp_start;
        __u16 orig_src_port = bpf_ntohs(inner_ports[0]); // Our original source port
        __u16 orig_dst_port = bpf_ntohs(inner_ports[1]); // Original destination port

        // Reconstruct key from the inner (original) packet
        struct timing_key key = {
            .src_port = orig_src_port,       // Our original ephemeral port
            .dst_port = orig_dst_port,       // Original target port
            .dst_ip = inner_ip->daddr,       // Original target IP (network order)
        };

        struct timing_value *val = bpf_map_lookup_elem(&timing_map, &key);
        if (val) {
            val->response_ts_ns = bpf_ktime_get_ns();
            val->flags |= (8 | TIMING_VERSION_1);   // bit 3: icmp, version 1
            val->port_state = 3;                      // unreachable
            val->response_ttl = ip->ttl;              // outer IP TTL
            val->response_win = 0;                    // no TCP window for ICMP
        } else {
            struct timing_value new_val = {
                .syn_ts_ns = 0,
                .response_ts_ns = bpf_ktime_get_ns(),
                .flags = 8 | TIMING_VERSION_1,        // icmp only, version 1
                .port_state = 3,                       // unreachable
                .response_ttl = ip->ttl,
                .response_win = 0,
            };
            bpf_map_update_elem(&timing_map, &key, &new_val, BPF_NOEXIST);
        }

        // Redirect ICMP unreachable to AF_XDP socket for userspace handling
        return bpf_redirect_map(&xsk_map, 0, XDP_PASS);
    }

    // Not TCP or ICMP — pass through
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "MIT";
