# Go + eBPF Packet Counter Project ✅

This project includes a user-space application written in **Go** and an **eBPF XDP** program written in **C**. The goal is to count incoming network packets and read this counter using Go.

## 🎯 Project Status: SUCCESSFUL
- ✅ eBPF XDP program is working
- ✅ Go application successfully compiles and runs
- ✅ Runs smoothly in Docker container
- ✅ Comprehensive documentation ready

## 📁 Project Structure

```
ebpf-golang/
├── ebpf/
│   ├── packet_count.c          # eBPF XDP program (C)
│   └── bpf/
│       └── bpf_helpers.h       # eBPF helper functions
├── bpftrace-examples/          # bpftrace examples
├── main.go                     # Go application
├── main_port_monitor.go        # SSH port monitoring application
├── LICENSE                     # MIT License
├── Makefile                    # Build and run commands
├── Dockerfile                  # Docker configuration
├── docker-compose.yml          # Docker Compose
├── README.md                   # This file
└── DEVELOPMENT.md              # Development guide
```

---

## 🚀 Quick Start (Docker - Recommended)

### Prerequisites
- Docker and Docker Compose installed
- Linux environment (WSL2 or Linux distribution)

### Running
```bash
# Clone or download the project
git clone <repository-url>
cd ebpf-golang

# Run with Docker
docker-compose up --build
```

### Expected Output
```
Creating ebpf-golang_ebpf-app_1 ... done
Attaching to ebpf-golang_ebpf-app_1
ebpf-app_1  | Counting packets... Press Ctrl+C to exit
```

---

## 🔧 Manual Installation (Linux)

### Requirements
```bash
# For Ubuntu/Debian
sudo apt update
sudo apt install -y golang-go clang llvm libelf-dev bpftool linux-libc-dev

# Go eBPF tools
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

### Building and Running
```bash
# 1. Compile the eBPF program and generate Go bindings
go generate

# 2. Compile the Go application
go build -o packet-counter main.go

# 3. Run with root privileges
sudo ./packet-counter
```

---

## 🔍 How It Works?

1. **eBPF XDP Program** (`packet_count.c`):
   - Captures every packet from the network card
   - Keeps packet count in a map
   - Uses XDP_PASS to allow packets to continue normal flow

2. **Go Application** (`main.go`):
   - Loads the eBPF program into the kernel
   - Attaches it to the network interface as XDP
   - Periodically reads and displays the packet count

3. **Docker Environment**:
   - Runs in privileged mode (required for eBPF)
   - Multi-stage build containing all necessary tools
   - Includes kernel headers and eBPF toolchain

---

## 📚 Additional Resources

- **`DEVELOPMENT.md`**: Development guide and workflow
- **`bpftrace-examples/`**: Advanced eBPF examples
- **Docker logs**: Follow outputs with `docker-compose logs -f`

---

## 🛠️ Development Notes

### Resolved Issues
- ✅ bpf2go function naming issues fixed
- ✅ Docker build issues (kernel headers, asm/types.h) resolved
- ✅ eBPF helper functions provided with custom header
- ✅ Go module compatibility ensured

### Testing
To test real network traffic inside the container:
```bash
# Generate traffic with Ping
ping -c 5 8.8.8.8

# Observe the increase in packet count
```

---

## 🛡️ Security Example: SSH Port Monitoring (eBPF)

This project also includes an example of eBPF + Go that detects and logs TCP connections to the SSH port (22).

### Compilation and Execution

```bash
make run-port-monitor
```
or manually:
```bash
# Generate eBPF Go bindings
GOOS=linux go generate -run=PortMonitor ./main_port_monitor.go
# Compile the Go application
GOOS=linux go build -o port-monitor main_port_monitor.go
# Start the application (with root privileges)
sudo ./port-monitor
```

### Example Output
```
Monitoring SSH port (22) connections... (interface: eth0)
Press Ctrl+C to exit
2025/06/12 13:37:12 SSH connection attempt: 192.168.1.100:54321 -> 192.168.1.10:22
```

> To change the monitored port, update the `watch_port` variable in the `ebpf/port_monitor.c` file.

---

## 📄 License

This project is licensed under the MIT License.
