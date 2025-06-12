# Go + eBPF Development Guide

This document contains detailed information and practical examples on programming with Go and eBPF.

## 📚 Contents

1. [eBPF Basics](#ebpf-basics)
2. [eBPF with Go](#ebpf-with-go)
3. [Project Structure](#project-structure)
4. [Development Workflow](#development-workflow)
5. [Debug and Troubleshooting](#debug-and-troubleshooting)
6. [Performance Optimization](#performance-optimization)
7. [Advanced Topics](#advanced-topics)

---

## 🔬 eBPF Basics

### What is eBPF?
- **Extended Berkeley Packet Filter** (eBPF)
- Technology for running safe code within the kernel
- No need to recompile the kernel
- High performance and low overhead

### Use Cases
- **Network Monitoring**: Packet analysis, DDoS protection
- **Security**: System call monitoring, intrusion detection
- **Performance**: CPU profiling, memory tracking
- **Observability**: Distributed tracing, metrics collection

### eBPF Program Types
```c
// XDP (eXpress Data Path) - Fastest, network card level
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) { ... }

// TC (Traffic Control) - Within network stack
SEC("tc")
int tc_prog(struct __sk_buff *skb) { ... }

// Tracepoint - Kernel events
SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx) { ... }

// Kprobe - Kernel function hooking
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) { ... }
```

---

## 🔗 eBPF with Go

### Why Go?
- **Simple Syntax**: Easier than C, faster than Python
- **Concurrency**: Simultaneous operations with Goroutines
- **Cross-platform**: Linux, Windows, macOS support
- **Rich Ecosystem**: Extensive library ecosystem

### cilium/ebpf Library
The most popular Go eBPF library:

```go
import (
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)
```

### bpf2go Tool
Converting C code to Go bindings:

```bash
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang PacketCount ebpf/packet_count.c
```

---

## 📁 Project Structure

### Recommended Directory Structure
```
project/
├── ebpf/                 # eBPF C code
│   ├── packet_count.c
│   └── bpf/
│       └── bpf_helpers.h
├── cmd/                  # Main applications
│   └── packet-counter/
│       └── main.go
├── internal/             # Internal packages
│   ├── ebpf/
│   └── metrics/
├── pkg/                  # Public packages
├── scripts/              # Helper scripts
│   ├── test-traffic.sh
│   ├── monitor-packets.sh
│   └── benchmark.sh
├── docker/               # Docker files
│   ├── Dockerfile
│   └── docker-compose.yml
├── docs/                 # Documentation
└── examples/             # Example code
```

### File Naming Conventions
- eBPF C files: `snake_case.c`
- Go files: `camelCase.go`
- Script files: `kebab-case.sh`
- Config files: `lowercase.yml`

---

## 🔄 Development Workflow

### 1. eBPF Program Development
```c
// ebpf/packet_count.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Map definition
struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

// XDP program
SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&packet_count, &key);
    
    if (count) {
        (*count)++;
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### 2. Creating Go Bindings
```go
// main.go
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang PacketCount ebpf/packet_count.c

import (
    "log"
    "time"
    
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // Remove memory limit for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal(err)
    }
    
    // Load eBPF program
    objs := packetcountObjects{}
    if err := loadPacketcountObjects(&objs, nil); err != nil {
        log.Fatal(err)
    }
    defer objs.Close()
    
    // Attach to network interface
    iface, err := net.InterfaceByName("eth0")
    if err != nil {
        log.Fatal(err)
    }
    
    l, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.CountPackets,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()
    
    // Read packet count periodically
    ticker := time.NewTicker(time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        var count uint64
        key := uint32(0)
        
        if err := objs.PacketCount.Lookup(&key, &count); err != nil {
            log.Printf("Error reading map: %v", err)
            continue        }
        
        log.Printf("Packets: %d", count)
    }
}
```

### 3. Test and Debug
```bash
# Compilation
make build

# Generate test traffic
make test-traffic

# Packet monitor
./scripts/monitor-packets.sh

# Performance test
./scripts/benchmark.sh
```

---

## 🐛 Debug and Troubleshooting

### Common Problems and Solutions

#### 1. "Program too large" Error
```bash
# Solution: LLVM optimization
clang -O2 -emit-llvm -c program.c -o - | \
llc -march=bpf -filetype=obj -o program.o
```

#### 2. "Invalid argument" Error
```go
// Kernel version check
info, err := ebpf.LoadProgram(&ebpf.ProgramSpec{
    Type: ebpf.XDP,
    // ...
})
```

#### 3. Map Lookup Failure
```c
// Always check map lookup result
__u64 *count = bpf_map_lookup_elem(&packet_count, &key);
if (!count) {
    return XDP_ABORTED;  // or handle error
}
```

### Debug Tools

#### bpftool
```bash
# List loaded programs
bpftool prog list

# View map contents
bpftool map dump id <MAP_ID>

# Show program information
bpftool prog show id <PROG_ID>
```

#### eBPF Verifier Logs
```go
spec.Instructions, err = asm.LoadFile("program.o")
if err != nil {
    log.Fatal(err)
}

// Enable verifier logs
prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
    LogLevel: 2,
    LogSize:  ebpf.DefaultVerifierLogSize,
})
```

---

## ⚡ Performance Optimization

### eBPF Program Optimization

#### 1. Minimal Map Operations
```c
// ❌ Inefficient
if (bpf_map_lookup_elem(&map, &key)) {
    bpf_map_update_elem(&map, &key, &new_value, BPF_ANY);
}

// ✅ Efficient  
__u64 *value = bpf_map_lookup_elem(&map, &key);
if (value) {
    (*value)++;
}
```

#### 2. Loop Unrolling
```c
// ❌ May not be accepted by verifier
for (int i = 0; i < 100; i++) {
    // process
}

// ✅ Unroll manually or use pragma
#pragma unroll
for (int i = 0; i < 16; i++) {
    // process
}
```

#### 3. Tail Calls
```c
// For complex programs
struct bpf_map_def SEC("maps") prog_array = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};

SEC("xdp")
int main_prog(struct xdp_md *ctx) {
    // Do initial processing
    bpf_tail_call(ctx, &prog_array, 1);
    return XDP_PASS;
}
```

### Go Application Optimization

#### 1. Efficient Map Reading
```go
// ❌ Create new variables each time
for {
    var key uint32 = 0
    var value uint64
    err := mapObj.Lookup(&key, &value)
    // ...
}

// ✅ Reuse variables
key := uint32(0)
var value uint64
for {
    err := mapObj.Lookup(&key, &value)
    // ...
}
```

#### 2. Batch Operations
```go
// For large maps, use batch operations
keys := make([]uint32, 100)
values := make([]uint64, 100)
count, err := mapObj.BatchLookup(nil, keys, values, nil)
```

#### 3. Worker Pool Pattern
```go
type Worker struct {
    mapObj *ebpf.Map
}

func (w *Worker) Process() {
    // Process map data
}

func main() {
    numWorkers := runtime.NumCPU()
    for i := 0; i < numWorkers; i++ {
        go worker.Process()
    }
}
```

---

## 🚀 Advanced Topics

### 1. Multi-Map Architecture
```c
// Different maps for different purposes
struct bpf_map_def SEC("maps") packet_count = { /* ... */ };
struct bpf_map_def SEC("maps") packet_size = { /* ... */ };
struct bpf_map_def SEC("maps") source_ips = { /* ... */ };
```

### 2. User-Kernel Communication
```go
// Ring buffer for high-throughput data
reader, err := ringbuf.NewReader(objs.Events)
if err != nil {
    log.Fatal(err)
}

for {
    record, err := reader.Read()
    if err != nil {
        log.Printf("Reading from ring buffer: %v", err)
        continue
    }
    
    // Process event
    processEvent(record.RawSample)
}
```

### 3. CO-RE (Compile Once, Run Everywhere)
```c
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    
    if (family != AF_INET) {
        return 0;
    }
    
    // Process IPv4 connection
    return 0;
}
```

### 4. Error Handling Best Practices
```go
func loadAndAttachProgram() error {
    // Load program
    objs := &packetcountObjects{}
    if err := loadPacketcountObjects(objs, nil); err != nil {
        return fmt.Errorf("loading eBPF objects: %w", err)
    }
    
    // Attach with proper cleanup
    link, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.CountPackets,
        Interface: iface.Index,
        Flags:     link.XDPGenericMode, // Fallback mode
    })
    if err != nil {
        objs.Close()
        return fmt.Errorf("attaching XDP program: %w", err)
    }
    
    // Setup cleanup
    go func() {
        defer link.Close()
        defer objs.Close()
        // Handle signals for graceful shutdown
    }()
    
    return nil
}
```

---

## 📖 Resources and Further Information

### Official Documentation
- [eBPF Documentation](https://ebpf.io/)
- [cilium/ebpf Library](https://github.com/cilium/ebpf)
- [Linux eBPF](https://www.kernel.org/doc/html/latest/bpf/)

### Books
- "Learning eBPF" - Liz Rice
- "BPF Performance Tools" - Brendan Gregg

### Online Resources
- [eBPF for Beginners](https://github.com/lizrice/ebpf-beginners)
- [Awesome eBPF](https://github.com/zoidbergwill/awesome-ebpf)
- [eBPF Examples](https://github.com/xdp-project/xdp-tutorial)

### Community
- [eBPF Slack](https://ebpf.io/slack)
- [Linux Plumbers Conference](https://www.linuxplumbersconf.org/)
- [eBPF Summit](https://ebpf.io/summit-2024/)

---

**Happy eBPF Coding! 🎉**
