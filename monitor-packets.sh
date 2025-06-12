#!/bin/bash
# Real-time packet monitoring script for eBPF packet counter

echo "📊 eBPF Packet Counter Monitor"
echo "============================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to show current time with color
show_time() {
    echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC}"
}

# Function to show status with color
show_status() {
    case $1 in
        "success") echo -e "${GREEN}✅ $2${NC}" ;;
        "warning") echo -e "${YELLOW}⚠️  $2${NC}" ;;
        "error") echo -e "${RED}❌ $2${NC}" ;;
        "info") echo -e "${BLUE}ℹ️  $2${NC}" ;;
        *) echo "$2" ;;
    esac
}

# Check if bpftool is available
if ! command -v bpftool >/dev/null 2>&1; then
    show_status "error" "bpftool not found. Please install bpftool."
    exit 1
fi

# Check if we're running as root or with sufficient privileges
if [ "$EUID" -ne 0 ] && ! groups | grep -q docker; then
    show_status "warning" "This script may require root privileges."
    show_status "info" "Run with 'sudo' if needed."
fi

echo "$(show_time) Starting monitor..."
echo ""

# Try to find the packet count map
echo "$(show_time) Searching for eBPF maps..."

# Function to find and monitor the packet count map
monitor_packets() {
    local map_id=""
    local prev_count=0
    local current_count=0
    local packets_per_sec=0
    local iteration=0
    
    while true; do
        # Try to find the packet_count map
        map_id=$(bpftool map list 2>/dev/null | grep -E "(packet_count|hash)" | head -1 | awk '{print $1}' | cut -d: -f1)
        
        if [ -n "$map_id" ]; then
            # Try to read the packet count
            current_count=$(bpftool map lookup id $map_id key 0 0 0 0 2>/dev/null | grep -o 'value.*' | cut -d' ' -f2 | head -1)
            
            if [ -n "$current_count" ] && [ "$current_count" -ge 0 ] 2>/dev/null; then
                # Calculate packets per second
                if [ $iteration -gt 0 ]; then
                    packets_per_sec=$((current_count - prev_count))
                fi
                
                # Show statistics
                printf "$(show_time) "
                printf "Toplam Paket: %'d | " $current_count
                printf "Son 1 saniye: %d pkt/s | " $packets_per_sec
                printf "Harita ID: %s\n" $map_id
                
                prev_count=$current_count
                iteration=$((iteration + 1))
            else
                show_status "warning" "Paket sayısı okunamadı (harita boş olabilir)"
            fi
        else
            show_status "warning" "eBPF packet_count haritası bulunamadı"
            show_status "info" "eBPF programının çalıştığından emin olun"
        fi
        
        sleep 1
    done
}

# Function to show eBPF program info
show_ebpf_info() {
    echo "$(show_time) eBPF Program Bilgileri:"
    echo "================================"
    
    # List loaded programs
    echo ""
    echo "Yüklü eBPF Programları:"
    bpftool prog list 2>/dev/null | grep -E "(xdp|packet)" || echo "XDP/packet programı bulunamadı"
    
    echo ""
    echo "eBPF Haritaları:"
    bpftool map list 2>/dev/null | grep -E "(packet|hash)" || echo "packet_count haritası bulunamadı"
    
    echo ""
    echo "================================"
    echo ""
}

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "$(show_time) Monitör durduruluyor..."
    show_status "success" "Monitör temiz bir şekilde kapatıldı"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Show initial info
show_ebpf_info

# Check if any XDP programs are loaded
if ! bpftool prog list 2>/dev/null | grep -q xdp; then
    show_status "warning" "XDP programı bulunamadı"
    show_status "info" "Önce Go uygulamasını çalıştırın: ./packet-counter"
    echo ""
    echo "$(show_time) XDP programı yüklenene kadar bekleniyor..."
    
    # Wait for XDP program to be loaded
    while ! bpftool prog list 2>/dev/null | grep -q xdp; do
        sleep 2
        printf "."
    done
    echo ""
    show_status "success" "XDP programı tespit edildi!"
    echo ""
fi

# Start monitoring
show_status "info" "Paket sayacı monitörü başlatıldı"
show_status "info" "Çıkmak için Ctrl+C kullanın"
echo ""

monitor_packets
