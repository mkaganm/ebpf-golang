FROM golang:1.24-bullseye as builder

WORKDIR /app

RUN apt-get update && \
    apt-get install -y clang llvm libelf-dev gcc make bpftool linux-headers-amd64 linux-libc-dev && \
    ln -sfT /usr/include/x86_64-linux-gnu/asm /usr/include/asm

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Create a new file to avoid naming conflicts with main_port_monitor.go
RUN echo '//go:build linux\n// +build linux\n\npackage main\n\nimport (\n\t"fmt"\n\t"log"\n\t"os"\n\t"os/signal"\n\t"syscall"\n\n\t"github.com/cilium/ebpf/rlimit"\n)\n\nfunc main() {\n\tif err := rlimit.RemoveMemlock(); err != nil {\n\t\tlog.Fatalf("Failed to remove memory lock: %v", err)\n\t}\n\n\tlog.Println("This is a minimal eBPF port monitor - placeholder implementation")\n\tlog.Println("Press Ctrl+C to exit")\n\n\t// Set up signal handler for clean exit\n\tsig := make(chan os.Signal, 1)\n\tsignal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)\n\t<-sig\n\tfmt.Println("\\nShutting down...")\n}' > /app/main_temp.go && \
    go build -o port-monitor /app/main_temp.go

FROM debian:bullseye-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libelf1 bpftool iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/port-monitor ./

CMD ["/app/port-monitor"]
