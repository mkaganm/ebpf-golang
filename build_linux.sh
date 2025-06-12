#!/bin/bash
# Build script for eBPF port monitoring application

set -e

echo "Installing dependencies..."
if command -v apt-get >/dev/null; then
    sudo apt-get update
    sudo apt-get install -y clang llvm libelf-dev gcc make linux-headers-$(uname -r)
elif command -v dnf >/dev/null; then
    sudo dnf install -y clang llvm elfutils-libelf-devel gcc make kernel-devel
else
    echo "Please install manually: clang, llvm, libelf-dev, gcc, make, kernel headers"
fi

echo "Installing bpf2go tool..."
go install github.com/cilium/ebpf/cmd/bpf2go@latest

echo "Generating eBPF bindings..."
GOPACKAGE=main $(go env GOPATH)/bin/bpf2go -cc clang PortMonitor ebpf/port_monitor.c -- -I/usr/include -I./ebpf/bpf -D__KERNEL__

echo "Building port monitor application..."
go build -o port-monitor main_port_monitor.go portmonitor_*.go

echo "Build complete: ./port-monitor"
echo "Run with sudo: sudo ./port-monitor [interface_name]"
