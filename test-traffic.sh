#!/bin/bash
# Test script to generate network traffic for packet counting verification

echo "🚀 eBPF Packet Counter Test Script"
echo "================================="
echo ""

# Function to show current time
show_time() {
    echo "[$(date '+%H:%M:%S')]"
}

# Check if we're running in Docker
if [ -f /.dockerenv ]; then
    echo "$(show_time) Running inside Docker container"
    INTERFACE="eth0"
else
    echo "$(show_time) Running on host system"
    # Try to detect the main network interface
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
fi

echo "$(show_time) Network interface used: $INTERFACE"
echo ""

# Test 1: Basic ping test
echo "$(show_time) Test 1: Starting basic ping test..."
echo "$(show_time) Sending 5 ping packets (8.8.8.8)"
ping -c 5 8.8.8.8 > /dev/null 2>&1
echo "$(show_time) ✅ Ping test completed"
echo ""

# Test 2: DNS queries
echo "$(show_time) Test 2: Starting DNS queries..."
echo "$(show_time) Sending 3 DNS queries"
for domain in google.com github.com stackoverflow.com; do
    nslookup $domain > /dev/null 2>&1
    echo "$(show_time) DNS query: $domain"
done
echo "$(show_time) ✅ DNS tests completed"
echo ""

# Test 3: HTTP requests (if curl is available)
if command -v curl >/dev/null 2>&1; then
    echo "$(show_time) Test 3: Starting HTTP requests..."
    echo "$(show_time) Sending 3 HTTP requests"
    for url in http://httpbin.org/ip http://httpbin.org/headers http://httpbin.org/user-agent; do
        curl -s --max-time 5 "$url" > /dev/null 2>&1
        echo "$(show_time) HTTP request: $url"
    done
    echo "$(show_time) ✅ HTTP testleri tamamlandı"
else
    echo "$(show_time) ⚠️  curl bulunamadı, HTTP testleri atlanıyor"
fi
echo ""

# Test 4: Generate some continuous traffic
echo "$(show_time) Test 4: Sürekli trafik oluşturma (10 saniye)..."
echo "$(show_time) Arka planda ping trafiği oluşturuluyor..."

# Start background ping
ping -i 0.5 8.8.8.8 > /dev/null 2>&1 &
PING_PID=$!

# Wait for 10 seconds
for i in {1..10}; do
    echo "$(show_time) Sürekli trafik: $i/10 saniye"
    sleep 1
done

# Stop background ping
kill $PING_PID 2>/dev/null
echo "$(show_time) ✅ Sürekli trafik testi tamamlandı"
echo ""

echo "$(show_time) 🎉 Tüm testler tamamlandı!"
echo "$(show_time) eBPF programının paket sayısındaki artışı gözlemleyin."
echo ""
echo "💡 İpucu: Go uygulamasının çıktısında paket sayısının arttığını görebilirsiniz."
