// Minimal XDP per-path counter: the skeleton of a NIC-side evidence arm (PREREG B11).
// Counts packets/bytes into a per-CPU array keyed by the low bits of the UDP source port
// (the spray entropy the fabric hashes on), then passes the packet through.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define N_PATHS 16

struct { 
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, N_PATHS);
    __type(key, __u32);
    __type(value, __u64);
} pkts SEC(".maps");

SEC("xdp")
int xdp_count(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data, *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > end) return XDP_PASS;
    __u32 key = __builtin_bswap16(udp->source) & (N_PATHS - 1);
    __u64 *v = bpf_map_lookup_elem(&pkts, &key);
    if (v) __sync_fetch_and_add(v, 1);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
