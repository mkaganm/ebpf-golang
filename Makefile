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
	@echo "  make test-traffic - Generate test traffic"
	@echo ""
	@echo "❓ Help:"
	@echo "  make help         - Show this help message"

# Generate eBPF code and Go bindings
generate:
	@echo "🔧 Compiling eBPF code and generating Go bindings..."
	go generate ./...
	@echo "✅ Generate completed"

# Build the Go application
build: generate
	@echo "🏗️  Building Go application..."
	go build -o packet-counter main.go
	@echo "✅ Build completed: ./packet-counter"

# Run the application (requires sudo)
run: build
	@echo "🚀 Running the application (sudo required)..."
	@echo "💡 Press Ctrl+C to exit"
	sudo ./packet-counter

# Clean generated files
clean:
	@echo "🧹 Cleaning up temporary files..."
	rm -f packet-counter
	rm -f packet_count_bpfeb.go packet_count_bpfel.go
	rm -f packet_count_bpfeb.o packet_count_bpfel.o
	@echo "✅ Cleanup completed"

# Docker build
docker-build:
	@echo "🐳 Building Docker image..."
	docker-compose build
	@echo "✅ Docker build completed"

# Docker run
docker-run:
	@echo "🐳 Running in Docker container..."
	@echo "💡 Use Ctrl+C to stop"
	docker-compose up

# Docker stop
docker-stop:
	@echo "🛑 Stopping Docker container..."
	docker-compose down
	@echo "✅ Docker container stopped"

# Generate test traffic
test-traffic:
	@echo "🧪 Generating test traffic..."
	@if [ -f test-traffic.sh ]; then \
		chmod +x test-traffic.sh && ./test-traffic.sh; \
	else \
		echo "❌ test-traffic.sh file not found"; \
	fi

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "📦 Installing dependencies (Ubuntu/Debian)..."
	sudo apt update
	sudo apt install -y golang-go clang llvm libelf-dev bpftool linux-libc-dev
	go install github.com/cilium/ebpf/cmd/bpf2go@latest
	@echo "✅ Dependencies installed"

# Check system requirements
check:
	@echo "🔍 Checking system requirements..."
	@echo ""
	@echo "Go version:"
	@go version || echo "❌ Go not found"
	@echo ""
	@echo "Clang version:"
	@clang --version | head -1 || echo "❌ Clang not found"
	@echo ""
	@echo "LLVM version:"
	@llc --version | head -1 || echo "❌ LLVM not found"
	@echo ""
	@echo "bpftool:"
	@bpftool version 2>/dev/null || echo "❌ bpftool not found"
	@echo ""
	@echo "Docker:"
	@docker --version || echo "❌ Docker not found"

# Port monitor eBPF example (security)
build-port-monitor:
	@echo "🔒 Compiling port monitoring eBPF program..."
	go generate -run=PortMonitor ./main_port_monitor.go
	go build -o port-monitor main_port_monitor.go
	@echo "✅ port-monitor compiled."

run-port-monitor: build-port-monitor
	@echo "🚦 Monitoring SSH port (22)..."
	sudo ./port-monitor
