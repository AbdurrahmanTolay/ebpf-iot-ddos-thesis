#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define THRESHOLD 50  // Packet threshold per IP

struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),   // IPv4 address
    .value_size = sizeof(__u32), // Packet count
    .max_entries = 1024,
};

// Helper function to convert IP address to string
static __always_inline void ip_to_str(__u32 ip, char *buf) {
    __u8 *bytes = (__u8 *)&ip;
    bpf_snprintf(buf, 32, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

SEC("xdp")
int udp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Parse UDP header
    struct udphdr *udph = (void *)iph + iph->ihl * 4;
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u32 *count = bpf_map_lookup_elem(&packet_count, &src_ip);
    __u32 new_count = 1;

    if (count) {
        new_count = *count + 1;
        bpf_map_update_elem(&packet_count, &src_ip, &new_count, BPF_ANY);
    } else {
        bpf_map_update_elem(&packet_count, &src_ip, &new_count, BPF_ANY);
    }

    // Log if threshold exceeded
    if (new_count == THRESHOLD) {
        char msg[64];
        ip_to_str(src_ip, msg);
        bpf_trace_printk("ALERT: Suspicious UDP flood from %s\n", msg);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
// eBPF XDP program source code placeholder
