# Go + eBPF Packet Counter Makefile

.PHONY: help build run clean docker-build docker-run docker-stop generate test-traffic

# Default target
help:
	@echo "🛠️  Go + eBPF Packet Counter - Makefile Commands"
	@echo "=================================================="
	@echo ""
	@echo "📦 Development:"
	@echo "  make generate     - Compile eBPF code and generate Go bindings"
	@echo "  make build        - Build Go application"
	@echo "  make run          - Run the application (sudo required)"
	@echo "  make clean        - Clean temporary files"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run   - Run in Docker container"
	@echo "  make docker-stop  - Stop Docker container"
	@echo ""
	@echo "🧪 Test:"
	@echo "  make test-traffic - Test trafiği oluştur"
	@echo ""
	@echo "❓ Yardım:"
	@echo "  make help         - Bu yardım mesajını göster"

# Generate eBPF code and Go bindings
generate:
	@echo "🔧 eBPF kodu derleniyor ve Go binding'leri oluşturuluyor..."
	go generate ./...
	@echo "✅ Generate işlemi tamamlandı"

# Build the Go application
build: generate
	@echo "🏗️  Go uygulaması derleniyor..."
	go build -o packet-counter main.go
	@echo "✅ Build işlemi tamamlandı: ./packet-counter"

# Run the application (requires sudo)
run: build
	@echo "🚀 Uygulama çalıştırılıyor (sudo gerekli)..."
	@echo "💡 Çıkmak için Ctrl+C kullanın"
	sudo ./packet-counter

# Clean generated files
clean:
	@echo "🧹 Geçici dosyalar temizleniyor..."
	rm -f packet-counter
	rm -f packet_count_bpfeb.go packet_count_bpfel.go
	rm -f packet_count_bpfeb.o packet_count_bpfel.o
	@echo "✅ Temizlik tamamlandı"

# Docker build
docker-build:
	@echo "🐳 Docker image'ı oluşturuluyor..."
	docker-compose build
	@echo "✅ Docker build tamamlandı"

# Docker run
docker-run:
	@echo "🐳 Docker konteynerında çalıştırılıyor..."
	@echo "💡 Durdurmak için Ctrl+C kullanın"
	docker-compose up

# Docker stop
docker-stop:
	@echo "🛑 Docker konteyneri durduruluyor..."
	docker-compose down
	@echo "✅ Docker konteyneri durduruldu"

# Generate test traffic
test-traffic:
	@echo "🧪 Test trafiği oluşturuluyor..."
	@if [ -f test-traffic.sh ]; then \
		chmod +x test-traffic.sh && ./test-traffic.sh; \
	else \
		echo "❌ test-traffic.sh dosyası bulunamadı"; \
	fi

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "📦 Bağımlılıklar kuruluyor (Ubuntu/Debian)..."
	sudo apt update
	sudo apt install -y golang-go clang llvm libelf-dev bpftool linux-libc-dev
	go install github.com/cilium/ebpf/cmd/bpf2go@latest
	@echo "✅ Bağımlılıklar kuruldu"

# Check system requirements
check:
	@echo "🔍 Sistem gereksinimleri kontrol ediliyor..."
	@echo ""
	@echo "Go sürümü:"
	@go version || echo "❌ Go bulunamadı"
	@echo ""
	@echo "Clang sürümü:"
	@clang --version | head -1 || echo "❌ Clang bulunamadı"
	@echo ""
	@echo "LLVM sürümü:"
	@llc --version | head -1 || echo "❌ LLVM bulunamadı"
	@echo ""
	@echo "bpftool:"
	@bpftool version 2>/dev/null || echo "❌ bpftool bulunamadı"
	@echo ""
	@echo "Docker:"
	@docker --version || echo "❌ Docker bulunamadı"

# Port monitor eBPF örneği (güvenlik)
build-port-monitor:
	@echo "🔒 Port izleme eBPF programı derleniyor..."
	go generate -run=PortMonitor ./main_port_monitor.go
	go build -o port-monitor main_port_monitor.go
	@echo "✅ port-monitor derlendi."

run-port-monitor: build-port-monitor
	@echo "🚦 SSH portu (22) izleniyor..."
	sudo ./port-monitor
