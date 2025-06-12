# Modern Linux Observability with Go (Golang) and eBPF: A Detailed Guide

## Introduction

In modern cloud infrastructures, microservice architectures, and high-performance systems, system observability and network traffic analysis are critically important. The eBPF (extended Berkeley Packet Filter) technology provided by the Linux kernel allows us to observe and analyze the system securely and flexibly without delving deep into the kernel. Go (Golang), on the other hand, is a popular, fast, and efficient language for system programming and network applications. In this article, we will explore how to integrate eBPF with Go, with practical examples and detailed explanations. Additionally, we will cover real-world use cases, performance tips, and advanced eBPF techniques.

---

## 1. What is eBPF?

eBPF is a technology that allows us to write secure and high-performance mini-programs running in the Linux kernel. eBPF programs are loaded into the kernel and can observe or manipulate various events such as network packets, system calls, and tracepoints. eBPF is the modern and extended version of the classic Berkeley Packet Filter (BPF).

### Key Features of eBPF
- **Performance:** Data is collected with minimal overhead as it operates in kernel-space.
- **Security:** eBPF programs are verified by the kernel and do not compromise system stability. Programs are analyzed by a verifier before being loaded.
- **Flexibility:** It can be used for network traffic monitoring, system call tracking, performance measurement, security, debugging, and more.
- **Dynamism:** New eBPF programs can be loaded into a running system without recompiling the kernel.
- **Map and Event Support:** Maps and events are used for data sharing between user space and the kernel.

### Use Cases
- Monitoring and filtering network packets (firewall, DDoS protection, traffic analysis)
- Tracking system calls (security, auditing, performance)
- Measuring performance and latency (profiling, tracing, monitoring)
- Security and attack detection (IDS/IPS, sandboxing)
- Dynamic observability and debugging

#### eBPF's Role in the Linux Ecosystem
- **XDP (eXpress Data Path):** Used to process network packets at the earliest stage in the kernel.
- **tc (Traffic Control):** eBPF programs can be used to shape and filter network traffic.
- **kprobes/uprobes/tracepoints:** Hooks can be added with eBPF to monitor kernel and user-space functions.

---

## 2. Using eBPF with Go

Go is ideal for loading, managing, and reading data from eBPF programs in user space. eBPF programs running on the kernel side are typically written in C. The most popular library for integrating eBPF with Go is [Cilium eBPF](https://github.com/cilium/ebpf). This library simplifies operations such as loading eBPF objects, working with maps, listening to events, and attaching hooks.

### Required Tools and Setup
- **Linux kernel 4.8+:** Required for eBPF support. Newer kernels offer more eBPF features.
- **Go:** https://golang.org/
- **Cilium eBPF Go package:** https://github.com/cilium/ebpf
- **LLVM/Clang:** Required for compiling eBPF bytecode.
- **bpftool:** A handy tool for inspecting and managing eBPF objects.

Setup (PowerShell):

```powershell
go install github.com/cilium/ebpf/cmd/bpf2go@latest
go get github.com/cilium/ebpf
```

Additionally, the following packages may be useful on Linux:

```bash
sudo apt-get install clang llvm libelf-dev gcc make bpftool linux-headers-$(uname -r)
```

---

## 3. Basics of eBPF Programs

eBPF programs are loaded at specific points (hooks) in the kernel and run there. Programs are written in C and compiled to eBPF bytecode using LLVM/Clang. In user space, these programs are loaded with Go, data is read/written through maps, and events are listened to.

### eBPF Program Types
- **XDP:** Processes network packets at the earliest stage in the kernel.
- **Socket Filter:** Filters packets passing through a specific socket.
- **Kprobe/Uprobe:** Monitors kernel or user-space functions.
- **Tracepoint:** Monitors kernel events.
- **Cgroup/Sched:** Monitors cgroup and scheduler events.

### Maps and Events
- **Map:** Provides data sharing between the kernel and user space. There are different types such as array, hash, and perf event.
- **Perf Event:** Used to send events from the kernel to the user space.

---

## 4. A Simple eBPF Program: Counting Network Packets

### 4.1. eBPF Program (Written in C)

`packet_count.c`:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} packet_count SEC(".maps");

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
```

This program counts every passing packet and stores it in a map. It works at the earliest stage of the kernel with XDP, providing minimal latency and high performance.

### 4.2. Loading the eBPF Program with Go and Reading Results

Generate Go bindings with `bpf2go`:

```powershell
bpf2go -cc clang.exe PacketCount packet_count.c -- -I"C:\path\to\linux-headers\include"
```

Load the eBPF program with Go and read the counter value:

```go
package main

import (
    "fmt"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "os"
    "os/signal"
    "syscall"
)

func main() {
    // Load the eBPF object
    objs := PacketCountObjects{}
    if err := LoadPacketCountObjects(&objs, nil); err != nil {
        panic(err)
    }
    defer objs.Close()

    // Attach to the XDP hook
    l, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.CountPackets,
        Interface: 2, // Network interface index (e.g., 2 for eth0)
    })
    if err != nil {
        panic(err)
    }
    defer l.Close()

    // Exit on Ctrl+C
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    fmt.Println("Counting packets... Press Ctrl+C to exit")
    <-sig

    // Read the counter value
    var key uint32
    var value uint64
    if err := objs.PacketCount.Lookup(&key, &value); err != nil {
        panic(err)
    }
    fmt.Printf("Total packets: %d\n", value)
}
```

#### Code Explanation
- `PacketCountObjects` and `LoadPacketCountObjects` functions are automatically generated by bpf2go.
- The eBPF program is loaded to a specific network interface using `link.AttachXDP`.
- The counter value is read from the map.

#### Important Notes
- The network interface index must be specified correctly. You can view the interface indices with the `ip link` command.
- Root privileges are required to load the eBPF program.
- The map definitions used in the kernel and Go sides must match exactly.

---

## 5. Is it Possible to Use eBPF Without Writing C Code?

In most cases, eBPF programs are written in C on the kernel side. This is because direct interaction with the kernel and a compiler (LLVM/Clang) are required. It is not possible to write or compile eBPF bytecode directly with Go. However:

- You can only perform user-space operations (loading, data reading, event listening) with Go.
- With tools like bpftrace or bcc, you can write high-level eBPF scripts without writing C code, but these do not work in integration with Go.
- There are projects in other languages like Rust (e.g., aya) for writing eBPF, but there is no native solution for Go.

### High-Level eBPF with bpftrace

bpftrace allows you to write eBPF programs at a higher level, with a C-like DSL. For example:

```bpftrace
kprobe:do_sys_open {
    printf("%s %s\n", comm, str(arg1));
}
```

This script prints the process name and file name every time a file is opened. However, it is not possible to directly integrate bpftrace scripts with Go.

---

## 6. Real-World eBPF Use Cases

### 6.1. Network Security and Monitoring
- **Cilium:** Uses eBPF for network security and observability in Kubernetes. It enforces network policies at the kernel level.
- **Katran:** Uses XDP-based eBPF programs to detect and mitigate DDoS attacks.
- **Sample Code:** A simple XDP eBPF program to count incoming packets:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} packet_count SEC(".maps");

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
```

---

### 6.2. Security and Event Detection
- **Falco:** Monitors system calls with eBPF to detect security events.
- **Tracee:** A runtime security and monitoring tool developed by Aqua Security, based on eBPF.
- **Sample Code:** A bpftrace script to monitor a file open system call:

```bpftrace
kprobe:do_sys_open {
    printf("%s %s\n", comm, str(arg1));
}
```

---

### 6.3. Performance and Observability
- **bcc, bpftrace:** Tools for dynamic observability and debugging. They provide detailed analysis at the kernel and application levels.
- **perf, sysdig:** Analyze system performance and events with eBPF.
- **Sample Code:** A bpftrace script to measure the duration of a function:

```bpftrace
uprobe:/usr/bin/myapp:myfunc
{
    @start[tid] = nsecs;
}
uretprobe:/usr/bin/myapp:myfunc
{
    printf("Duration: %d ns\n", nsecs - @start[tid]);
    delete(@start[tid]);
}
```

---

### 6.4. Other Use Cases
- **Sandboxing:** eBPF can be used to isolate applications and enhance their security.
- **Custom Monitoring:** You can develop your own custom observability and metric collection tools.
- **Sample Code:** Reading a counter from an eBPF map with Go:

```go
var key uint32 = 0
var value uint64
if err := objs.PacketCount.Lookup(&key, &value); err == nil {
    fmt.Printf("Total packets: %d\n", value)
}
```

---

## 7. Performance, Security, and Advanced Techniques

### 7.1. Performance Tips
- eBPF programs should be as short and fast as possible. The kernel verifier limits the complexity of the programs.
- Minimize map access.
- Processing packets with XDP is much faster than traditional iptables or netfilter.

### 7.2. Security
- eBPF programs are analyzed by the kernel verifier before being loaded. Errors like infinite loops or memory overflows are not allowed.
- eBPF programs can only access permitted areas.

### 7.3. Advanced Techniques
- **Tail Calls:** Chained calls between eBPF programs are possible.
- **Helper Functions:** Advanced operations can be performed with the kernel's helper functions.
- **Ring Buffer:** Can be used for high-performance event transfer.

---

## 8. Resources and Further Reading

- [Cilium eBPF Go Library](https://github.com/cilium/ebpf)
- [eBPF.io](https://ebpf.io/)
- [bpftrace](https://github.com/iovisor/bpftrace)
- [Linux eBPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)
- [Awesome eBPF](https://github.com/zoidbergwill/awesome-ebpf)
- [Brendan Gregg eBPF Resources](http://www.brendangregg.com/ebpf.html)
- [Liz Rice: Learning eBPF](https://www.youtube.com/watch?v=Qh5kC6w7g1c)

---

## Conclusion

It is possible to develop high-performance, secure, and flexible observability tools for modern Linux systems with Go and eBPF. With the power of eBPF, you can collect and analyze data at the kernel level without delving deep into the system. Go makes it easy to manage and integrate these programs. The eBPF ecosystem is rapidly growing, and new use cases are emerging. You can start exploring Go and eBPF to develop your own observability, security, or performance analysis tools. Feel free to leave a comment with your questions or contributions!

## Sample Project: Packet Counter with Go + eBPF

In this section, all the code and explanations above are demonstrated through a sample project called `ebpf-golang`. Project structure:

- `ebpf/packet_count.c`: eBPF XDP program (C)
- `main.go`: Application that loads the eBPF program and reads the packet counter with Go
- `bpftrace-examples/`: Example scripts that can be used with bpftrace
- `README.md`: Project description and usage instructions

### 1. eBPF Program (C)

`ebpf/packet_count.c`:
```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include "bpf/bpf_helpers.h"

// Packet count eBPF map
struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

// XDP program - called for each packet
SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *count;
    
    // Get the current counter from the map
    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        // Increment the counter (atomic operation)
        __sync_fetch_and_add(count, 1);
    }
    
    // Pass the packet (XDP_PASS)
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### 2. Loading the eBPF Program and Reading the Counter with Go

`main.go`:
```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -go-package main packetcount ebpf/packet_count.c -- -I/usr/include -Iebpf

func main() {
	// Load eBPF objects
	objs := packetcountObjects{}
	if err := loadPacketcountObjects(&objs, nil); err != nil {
		panic(fmt.Sprintf("Error loading eBPF objects: %v", err))
	}
	defer objs.Close()

	// Attach XDP program to the network interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: 2, // Usually interface 2 for eth0
	})
	if err != nil {
		panic(fmt.Sprintf("Error attaching XDP: %v", err))
	}
	defer l.Close()

	// Wait for SIGINT/SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Counting packets... Press Ctrl+C to exit")
	<-sig

	// Get and display the final packet count
	var key uint32 = 0
	var value uint64
	if err := objs.PacketCount.Lookup(&key, &value); err != nil {
		panic(fmt.Sprintf("Error reading value from map: %v", err))
	}
	fmt.Printf("Total packet count: %d\n", value)
}
```

### 3. bpftrace Scripts

`bpftrace-examples/README.md`:
```bpftrace
kprobe:do_sys_open {
    printf("%s %s\n", comm, str(arg1));
}

uprobe:/usr/bin/myapp:myfunc
{
    @start[tid] = nsecs;
}
uretprobe:/usr/bin/myapp:myfunc
{
    printf("Duration: %d ns\n", nsecs - @start[tid]);
    delete(@start[tid]);
}
```

### 4. Installation and Running

1. Install the required tools: Go, clang, llvm, libelf-dev, bpftool
2. Compile the eBPF program and generate Go bindings:
   ```powershell
   go install github.com/cilium/ebpf/cmd/bpf2go@latest
   bpf2go -cc clang.exe PacketCount ebpf/packet_count.c -- -I"C:/path/to/linux-headers/include"
   ```
3. Build the Go application:
   ```powershell
   go build -o packet-counter main.go
   ```
4. Run the application (may require root privileges):
   ```powershell
   .\packet-counter.exe
   ```

---

Now, all the examples and explanations in the blog are demonstrated through this sample project.

---

## 3. Practical Example: Packet Counter

In this section, we will create a simple yet effective eBPF application that counts network packets using XDP. Our project includes both the eBPF kernel code and the Go user-space application.

### Project Structure

```
ebpf-golang/
├── main.go                  # Go user-space application
├── ebpf/
│   ├── packet_count.c       # eBPF kernel program
│   └── bpf/
│       └── bpf_helpers.h    # eBPF helper functions
├── Dockerfile               # Container configuration
├── docker-compose.yml       # Easy deployment
├── go.mod                   # Go dependencies
└── README.md               # Project documentation
```

### eBPF Kernel Program (C)

First, let's write our eBPF program that will count packets using XDP:

```c
// ebpf/packet_count.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include "bpf/bpf_helpers.h"

// Packet count eBPF map
struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

// XDP program - called for each packet
SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *count;
    
    // Get the current counter from the map
    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        // Increment the counter (atomic operation)
        __sync_fetch_and_add(count, 1);
    }
    
    // Pass the packet (XDP_PASS)
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

### Go User-Space Application

Now let's write the Go application that will load the eBPF program and read the packet count:

```go
// main.go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -go-package main packetcount ebpf/packet_count.c -- -I/usr/include -Iebpf

func main() {
	// Load eBPF objects
	objs := packetcountObjects{}
	if err := loadPacketcountObjects(&objs, nil); err != nil {
		panic(fmt.Sprintf("Error loading eBPF objects: %v", err))
	}
	defer objs.Close()

	// Attach XDP program to the network interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: 2, // Usually interface 2 for eth0
	})
	if err != nil {
		panic(fmt.Sprintf("Error attaching XDP: %v", err))
	}
	defer l.Close()

	// Wait for SIGINT/SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Counting packets... Press Ctrl+C to exit")
	<-sig

	// Get and display the final packet count
	var key uint32 = 0
	var value uint64
	if err := objs.PacketCount.Lookup(&key, &value); err != nil {
		panic(fmt.Sprintf("Error reading value from map: %v", err))
	}
	fmt.Printf("Total packet count: %d\n", value)
}
```

### Docker Deployment

We use Docker for easy deployment:

```dockerfile
# Dockerfile
FROM golang:1.24-bullseye as builder

WORKDIR /app

# Install eBPF development tools
RUN apt-get update && \
    apt-get install -y clang llvm libelf-dev gcc make bpftool linux-libc-dev && \
    ln -sfT /usr/include/x86_64-linux-gnu/asm /usr/include/asm

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generate Go bindings with bpf2go and build
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest && \
    $(go env GOPATH)/bin/bpf2go -go-package main packetcount ebpf/packet_count.c -- -I/usr/include -I./ebpf && \
    go build -o packet-counter .

# Runtime image
FROM debian:bullseye-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libelf1 bpftool iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/packet-counter ./

CMD ["/app/packet-counter"]
```

### Running and Testing

You can run the application with Docker Compose:

```yaml
# docker-compose.yml
version: '3.8'
services:
  ebpf-packet-counter:
    build: .
    privileged: true
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
```

Running:
```bash
docker-compose up --build
```

### Successful Run Output

When the application runs successfully, you will see this output:
```
Counting packets... Press Ctrl+C to exit
```

This indicates that the eBPF program has been loaded into the kernel, attached to the XDP hook, and started listening to network traffic.

---

## 4. Advanced eBPF Techniques

### BPF Maps Types and Usages

eBPF offers different types of maps:

```c
// Hash map - for key-value pairs
struct bpf_map_def SEC("maps") connection_tracker = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct flow_stats),
    .max_entries = 10000,
};

// Per-CPU array - separate data for each CPU
struct bpf_map_def SEC("maps") cpu_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 256,
};

// Ring buffer - for event sending to user space
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,
};
```

### Event-Driven Monitoring

```go
// Go side event listening
func monitorEvents(eventMap *ebpf.Map) {
    reader, err := ringbuf.NewReader(eventMap)
    if err != nil {
        panic(err)
    }
    defer reader.Close()

    for {
        record, err := reader.Read()
        if err != nil {
            continue
        }
        
        // Parse and process the event
        processNetworkEvent(record.RawSample)
    }
}
```

### Performance Optimization

```c
// Inline functions - critical for performance
static __always_inline int process_packet(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Bounds checking - required for verifier
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;
    
    // Packet processing...
    return XDP_PASS;
}
```

---

## 5. Real World Use Cases

### 1. DDoS Protection System

```c
SEC("xdp")
int ddos_protection(struct xdp_md *ctx)
{
    // Rate limiting per IP
    struct iphdr *ip = get_ip_header(ctx);
    if (!ip) return XDP_PASS;
    
    __u32 src_ip = ip->saddr;
    __u64 *packet_count = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    
    if (packet_count && *packet_count > RATE_LIMIT_THRESHOLD) {
        return XDP_DROP; // Drop the packet
    }
    
    // Update the rate counter
    update_rate_counter(&src_ip);
    return XDP_PASS;
}
```

### 2. Application Performance Monitoring (APM)

```c
SEC("uprobe/http_request")
int trace_http_request(struct pt_regs *ctx)
{
    struct http_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    
    // Collect HTTP request information
    bpf_probe_read_user_str(event.url, sizeof(event.url), 
                           (void *)PT_REGS_PARM1(ctx));
    
    // Send the user space event
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}
```

### 3. Network Security Monitoring

```c
SEC("tc")
int network_security_monitor(struct __sk_buff *skb)
{
    struct security_event event = {};
    
    // Detection of suspicious network activity
    if (detect_suspicious_pattern(skb)) {
        event.alert_type = SUSPICIOUS_TRAFFIC;
        event.src_ip = get_src_ip(skb);
        event.dst_port = get_dst_port(skb);
        
        // Log the security event
        bpf_ringbuf_output(&security_events, &event, sizeof(event), 0);
    }
    
    return TC_ACT_OK;
}
```

---

## 6. Troubleshooting and Debug

### eBPF Program Debug

```bash
# Check the eBPF program load status
bpftool prog list

# View the map content
bpftool map dump id <map_id>

# View the program source code
bpftool prog dump xlated id <prog_id>

# Check the verifier logs
echo 1 > /proc/sys/kernel/bpf_stats_enabled
bpftool prog show id <prog_id> --verbose
```

### Go Debug

```go
// More detailed error messages in debug mode
func loadProgram() {
    spec, err := ebpf.LoadCollectionSpec("program.o")
    if err != nil {
        log.Printf("Error loading eBPF spec: %v", err)
        return
    }
    
    // Enable verifier logs
    coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
        Maps: ebpf.MapOptions{
            PinPath: "/sys/fs/bpf", // Pin the maps
        },
    })
    if err != nil {
        log.Printf("Error creating collection: %v", err)
        return
    }
}
```

### Common Issues

1. **Permission Denied:** Requires `CAP_SYS_ADMIN` privilege
2. **Verifier Errors:** Missing bounds checking or infinite loop
3. **Map Not Found:** Names generated by bpf2go may differ
4. **Kernel Compatibility:** Not all eBPF features are available in older kernels

---

## 7. Performance Tips

### eBPF Program Optimization

```c
// 1. Use inline functions
static __always_inline bool is_tcp_packet(struct iphdr *ip) {
    return ip->protocol == IPPROTO_TCP;
}

// 2. Branch prediction hints
if (__builtin_expect(condition, 1)) {
    // Likely true path
}

// 3. Use per-CPU maps - reduces locking overhead
struct bpf_map_def SEC("maps") per_cpu_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    // ...
};
```

### Go Performance

```go
// 1. Use map batch operations
keys := make([]uint32, batchSize)
values := make([]uint64, batchSize)
count, err := m.BatchLookup(keys, values, nil)

// 2. Use memory pool
var eventPool = sync.Pool{
    New: func() interface{} {
        return &NetworkEvent{}
    },
}

func processEvent() {
    event := eventPool.Get().(*NetworkEvent)
    defer eventPool.Put(event)
    // Process the event...
}

// 3. Use goroutine pool
func startWorkers(numWorkers int) {
    for i := 0; i < numWorkers; i++ {
        go worker()
    }
}
```

---

## 8. Conclusion

The combination of eBPF and Go offers a powerful solution for modern system observability, network security, and performance monitoring. In this article, we covered a practical example that can serve as a foundation for your real-world applications. 

### Key Benefits:
- **High Performance:** Minimal overhead in kernel-space
- **Security:** Safe code execution with verifier
- **Flexibility:** Dynamic program loading and updating
- **Observability:** Deep access to system internals

### Next Steps:
1. Explore the **Cilium/eBPF** documentation
2. Experiment with **bpftrace** for quick prototyping
3. Research production-ready eBPF projects like **Katran**, **Falco**, **Pixie**
4. Develop eBPF solutions for your own use cases

The eBPF ecosystem is rapidly evolving, with new features and capabilities being added. The best way to discover the potential of this technology is to experiment and develop projects using eBPF.