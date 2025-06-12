#include <linux/bpf.h>
#include "bpf/bpf_helpers.h"

// Compatible type definitions
#ifndef __u32
#define __u32 unsigned int
#endif
#ifndef __u64
#define __u64 unsigned long long
#endif

typedef __u32 u32;
typedef __u64 u64;

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
    .map_flags = 0,
};

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    u32 key = 0;
    u64 *value = bpf_map_lookup_elem(&packet_count, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
