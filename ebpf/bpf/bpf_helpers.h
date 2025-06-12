/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#include <linux/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static int (*bpf_map_update_elem)(void *map, const void *key, const void *value, unsigned long long flags) = (void *) 2;
static int (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static long long (*bpf_ktime_get_ns)(void) = (void *) 5;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *) 6;
static int (*bpf_get_prandom_u32)(void) = (void *) 7;
static int (*bpf_get_smp_processor_id)(void) = (void *) 8;
static int (*bpf_tail_call)(void *ctx, void *map, int index) = (void *) 12;
static int (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static int (*bpf_get_current_uid_gid)(void) = (void *) 15;
static int (*bpf_get_current_comm)(void *buf, int size_of_buf) = (void *) 16;
static int (*bpf_perf_event_output)(void *ctx, void *map, unsigned long long flags, void *data, int size) = (void *) 25;
static int (*bpf_get_stackid)(void *ctx, void *map, int flags) = (void *) 27;
static int (*bpf_probe_read_str)(void *dst, int size, const void *unsafe_ptr) = (void *) 45;

#endif /* __BPF_HELPERS_H */
