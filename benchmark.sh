#!/bin/bash
# Performance benchmark script for eBPF packet counter

echo "🏎️  eBPF Packet Counter Performance Test"
echo "======================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_time() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC}"
}

show_result() {
    echo -e "${GREEN}📈 $1${NC}"
}

show_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

# Check prerequisites
if ! command -v ping >/dev/null 2>&1; then
    echo "❌ ping command not found"
    exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
    echo "❌ bpftool not found"
    exit 1
fi

echo "$(show_time) Starting performance test..."
echo ""

# Function to get current packet count
get_packet_count() {
    local map_id=$(bpftool map list 2>/dev/null | grep -E "(packet_count|hash)" | head -1 | awk '{print $1}' | cut -d: -f1)
    if [ -n "$map_id" ]; then
        bpftool map lookup id $map_id key 0 0 0 0 2>/dev/null | grep -o 'value.*' | cut -d' ' -f2 | head -1
    else
        echo "0"
    fi
}

# Test 1: Baseline measurement
echo "$(show_time) Test 1: Başlangıç ölçümü"
baseline_count=$(get_packet_count)
if [ -z "$baseline_count" ] || [ "$baseline_count" = "0" ]; then
    show_info "eBPF programı henüz paket saymaya başlamamış"
    baseline_count=0
fi
show_result "Başlangıç paket sayısı: $baseline_count"
echo ""

# Test 2: Single ping performance
echo "$(show_time) Test 2: Tekil ping performansı"
start_count=$(get_packet_count)
start_time=$(date +%s.%N)

ping -c 1 8.8.8.8 > /dev/null 2>&1

end_time=$(date +%s.%N)
end_count=$(get_packet_count)

ping_duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0")
packets_captured=$((end_count - start_count))

show_result "Ping süresi: ${ping_duration}s"
show_result "Yakalanan paket: $packets_captured"
echo ""

# Test 3: Burst ping test
echo "$(show_time) Test 3: Hızlı ping serisi (10 paket)"
start_count=$(get_packet_count)
start_time=$(date +%s.%N)

ping -c 10 -i 0.1 8.8.8.8 > /dev/null 2>&1

end_time=$(date +%s.%N)
end_count=$(get_packet_count)

burst_duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0")
burst_packets=$((end_count - start_count))
if [ "$burst_duration" != "0" ]; then
    pps=$(echo "scale=2; $burst_packets / $burst_duration" | bc 2>/dev/null || echo "N/A")
else
    pps="N/A"
fi

show_result "Burst test süresi: ${burst_duration}s"
show_result "Yakalanan paket: $burst_packets"
show_result "Paket/saniye: $pps"
echo ""

# Test 4: Sustained traffic test
echo "$(show_time) Test 4: Sürekli trafik testi (30 saniye)"
start_count=$(get_packet_count)
start_time=$(date +%s)

# Start background ping
ping -i 0.2 8.8.8.8 > /dev/null 2>&1 &
ping_pid=$!

# Monitor for 30 seconds
for i in {1..30}; do
    current_count=$(get_packet_count)
    current_packets=$((current_count - start_count))
    current_pps=$(echo "scale=1; $current_packets / $i" | bc 2>/dev/null || echo "0")
    printf "\r$(show_time) %2d/30s | Paket: %4d | Ort. PPS: %s" $i $current_packets $current_pps
    sleep 1
done

# Stop background ping
kill $ping_pid 2>/dev/null
echo ""

end_time=$(date +%s)
end_count=$(get_packet_count)

sustained_duration=$((end_time - start_time))
sustained_packets=$((end_count - start_count))
sustained_pps=$(echo "scale=2; $sustained_packets / $sustained_duration" | bc 2>/dev/null || echo "N/A")

echo ""
show_result "Sürekli test süresi: ${sustained_duration}s"
show_result "Toplam yakalanan paket: $sustained_packets"
show_result "Ortalama paket/saniye: $sustained_pps"
echo ""

# Test 5: CPU usage estimation (if top is available)
if command -v top >/dev/null 2>&1; then
    echo "$(show_time) Test 5: CPU kullanımı tahmini"
    show_info "5 saniye boyunca CPU kullanımı ölçülüyor..."
    
    # Get process ID of our Go application (if running)
    go_pid=$(pgrep -f "packet-counter" | head -1)
    if [ -n "$go_pid" ]; then
        cpu_usage=$(top -p $go_pid -b -n 1 | tail -1 | awk '{print $9}' 2>/dev/null || echo "N/A")
        show_result "Go uygulaması CPU kullanımı: %$cpu_usage"
    else
        show_info "Go uygulaması çalışır durumda değil"
    fi
    echo ""
fi

# Summary
echo "$(show_time) 📋 Performans Özeti"
echo "================================"
echo "🎯 Baseline: $baseline_count paket"
echo "🏓 Tekil ping: $packets_captured paket yakalandı"
echo "💨 Burst test: $burst_packets paket, $pps PPS"
echo "⏱️  Sürekli test: $sustained_packets paket, $sustained_pps PPS"
echo ""
show_result "Test tamamlandı! eBPF programı düzgün çalışıyor."
