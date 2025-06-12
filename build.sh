#!/bin/bash
set -ex

# Install bpf2go tool if not available
if ! command -v bpf2go &> /dev/null; then
    echo "Installing bpf2go..."
    go install github.com/cilium/ebpf/cmd/bpf2go@latest
fi

# Set working directory to project root
cd "$(dirname "$0")"
pwd
ls -la

# Generate eBPF Go bindings
echo "Generating eBPF bindings..."
PATH=$PATH:$(go env GOPATH)/bin GOPACKAGE=main bpf2go -cc clang PortMonitor ebpf/port_monitor.c -- -I/usr/include -I./ebpf/bpf -D__KERNEL__

# List files to verify the generated files
echo "Generated files:"
ls -la portmonitor_*.go || echo "No PortMonitor*.go files found"

# Build the port monitor application
echo "Building port monitor application..."
go build -v -o port-monitor main_port_monitor.go portmonitor_*.go

echo "Build completed successfully: ./port-monitor"
