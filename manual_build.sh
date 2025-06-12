#!/bin/bash
# This script manually compiles the eBPF code and builds the Go application
# Use this if you're having trouble with the automated bpf2go approach

set -e

echo "=== Compiling eBPF Port Monitor ==="

# Install dependencies if needed
if [ "$(id -u)" -eq 0 ]; then
  if command -v apt-get > /dev/null; then
    echo "Installing dependencies with apt..."
    apt-get update
    apt-get install -y clang llvm libelf-dev bpftool linux-headers-$(uname -r)
  elif command -v dnf > /dev/null; then
    echo "Installing dependencies with dnf..."
    dnf install -y clang llvm elfutils-libelf-devel bpftool kernel-devel
  else
    echo "Warning: Unknown package manager, manually install dependencies"
  fi
fi

# Manually compile the eBPF C code to object file
echo "Compiling eBPF C code..."
clang -O2 -g -Wall -target bpf \
  -c ebpf/port_monitor.c \
  -o port_monitor.o \
  -I/usr/include -I./ebpf/bpf -D__KERNEL__

echo "eBPF object file created: port_monitor.o"
ls -la port_monitor.o

# Options from here:
# 1. Create a Go binary that embeds the object file
# 2. Use the embedded loader from cilium/ebpf
echo 
echo "To test the compiled eBPF program:"
echo "sudo bpftool prog load port_monitor.o /sys/fs/bpf/port_monitor"

echo
echo "For successful Docker builds, you may still want to use the simplified version"
echo "that's included in the Dockerfile."
