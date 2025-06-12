# Overview of eBPF Port Monitoring Project

## Project Structure

This project uses eBPF to monitor network traffic on specified ports. The current setup includes:

- `ebpf/port_monitor.c`: eBPF C code for port monitoring
- `main_port_monitor.go`: Go application that loads and manages eBPF programs

## Build Process

The build process has two paths:

1. **Docker build**: Uses a simplified implementation to ensure Docker builds succeed
2. **Local development**: Uses bpf2go to generate eBPF bindings

## For Local Development

To properly build this project locally:

1. Install dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install clang llvm libelf-dev gcc bpftool linux-headers-$(uname -r)

   # Fedora/RHEL
   sudo dnf install clang llvm elfutils-libelf-devel gcc bpftool kernel-devel
   ```

2. Generate eBPF bindings and build the application:
   ```bash
   # Install bpf2go tool
   go install github.com/cilium/ebpf/cmd/bpf2go@latest

   # Generate bindings
   GOPACKAGE=main $(go env GOPATH)/bin/bpf2go -cc clang PortMonitor ebpf/port_monitor.c -- -I/usr/include -I./ebpf/bpf -D__KERNEL__

   # Build application
   go build -o port-monitor main_port_monitor.go portmonitor_*.go
   ```

## Manual Troubleshooting

If you encounter errors with the bpf2go tool, you can manually compile the eBPF C code:

1. Compile eBPF C code to object file:
   ```bash
   clang -O2 -g -Wall -target bpf -c ebpf/port_monitor.c -o port_monitor.o -I./ebpf/bpf
   ```

2. Load the object file directly in your Go code rather than using bpf2go-generated code.
