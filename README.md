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
├── go.mod                      # Go module file
├── Dockerfile                  # Docker configuration
├── docker-compose.yml          # Docker Compose
├── tr-ebpf-golang.md          # Comprehensive documentation
└── README.md                   # This file
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

## 📚 Ek Kaynaklar

- **`tr-ebpf-golang.md`**: Detaylı Türkçe blog yazısı ve açıklamalar
- **`bpftrace-examples/`**: İleri seviye eBPF örnekleri
- **Docker logs**: `docker-compose logs -f` ile çıktıları takip edin

---

## 🛠️ Geliştirme Notları

### Çözülen Sorunlar
- ✅ bpf2go fonksiyon isimlendirme sorunları düzeltildi
- ✅ Docker build sorunları (kernel headers, asm/types.h) çözüldü  
- ✅ eBPF helper fonksiyonları custom header ile sağlandı
- ✅ Go modül uyumluluğu sağlandı

### Test Etme
Gerçek ağ trafiğini test etmek için konteyner içinde:
```bash
# Ping ile trafik oluştur
ping -c 5 8.8.8.8

# Paket sayısının artışını gözlemle
```

---

## 🛡️ Güvenlik Örneği: SSH Portu İzleme (eBPF)

Bu projede ayrıca, SSH portuna (22) gelen TCP bağlantılarını tespit eden ve loglayan bir eBPF + Go örneği de bulunmaktadır.

### Derleme ve Çalıştırma

```bash
make run-port-monitor
```
veya manuel olarak:
```bash
# eBPF Go bindinglerini oluştur
GOOS=linux go generate -run=PortMonitor ./main_port_monitor.go
# Go uygulamasını derle
GOOS=linux go build -o port-monitor main_port_monitor.go
# Uygulamayı başlat (root yetkisiyle)
sudo ./port-monitor
```

### Çıktı Örneği
```
SSH port (22) bağlantıları izleniyor... (interface: eth0)
Çıkmak için Ctrl+C
2025/06/12 13:37:12 SSH bağlantı denemesi: 192.168.1.100:54321 -> 192.168.1.10:22
```

> İzlenen portu değiştirmek için `ebpf/port_monitor.c` dosyasındaki `watch_port` değişkenini güncelleyebilirsiniz.

---

## 📄 Lisans
Bu proje MIT lisansı altında yayınlanmıştır.
