#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>  /* for IPPROTO_TCP constant */
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_map_def.h"

struct event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 128,
};

SEC("xdp")
int monitor_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;    // Port to monitor (e.g., 22 - SSH)
    __u16 watch_port = __constant_htons(22);
    if (tcp->dest == watch_port) {
        struct event_t evt = {};
        evt.src_ip = ip->saddr;
        evt.dst_ip = ip->daddr;
        evt.src_port = tcp->source;
        evt.dst_port = tcp->dest;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
