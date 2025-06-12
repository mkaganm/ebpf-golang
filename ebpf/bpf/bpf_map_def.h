#ifndef __BPF_MAP_DEF_H
#define __BPF_MAP_DEF_H

#include <linux/bpf.h>

/* Map definition structure that defines the map type, key and value sizes, 
 * max entries and other map flags. This definition is used in eBPF C code
 * and matches the format expected by the bpf2go tool.
 */
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

#endif /* __BPF_MAP_DEF_H */
