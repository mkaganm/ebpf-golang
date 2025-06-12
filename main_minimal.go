//go:build linux
// +build linux

// Package main provides a security monitoring tool using eBPF
// This version simulates security monitoring capabilities
package main

import (
	"fmt"
	"log"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// ConnectionAttempt represents a connection to a monitored port
type ConnectionAttempt struct {
	SourceIP    string
	SourcePort  uint16
	DestIP      string
	DestPort    uint16
	Timestamp   time.Time
	ProcessName string
	Suspicious  bool
}

// SecurityMonitor handles the security monitoring operations
type SecurityMonitor struct {
	monitoredPorts map[uint16]bool
	connections    []ConnectionAttempt
	suspiciousIPs  map[string]int
	mu             sync.Mutex
}

// NewSecurityMonitor creates a new security monitor
func NewSecurityMonitor() *SecurityMonitor {
	// Default ports to monitor (common attack targets)
	ports := map[uint16]bool{
		22:    true, // SSH
		23:    true, // Telnet
		3389:  true, // RDP
		445:   true, // SMB
		1433:  true, // MSSQL
		3306:  true, // MySQL
		5432:  true, // PostgreSQL
		6379:  true, // Redis
		27017: true, // MongoDB
	}

	return &SecurityMonitor{
		monitoredPorts: ports,
		connections:    []ConnectionAttempt{},
		suspiciousIPs:  make(map[string]int),
	}
}

// AddSuspiciousConnection adds a suspicious connection attempt
func (sm *SecurityMonitor) AddSuspiciousConnection(conn ConnectionAttempt) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	conn.Suspicious = true
	sm.connections = append(sm.connections, conn)
	sm.suspiciousIPs[conn.SourceIP]++

	log.Printf("[ALERT] Suspicious connection from %s:%d to %s:%d",
		conn.SourceIP, conn.SourcePort, conn.DestIP, conn.DestPort)

	// If we see multiple attempts from the same IP, report a potential attack
	if sm.suspiciousIPs[conn.SourceIP] >= 3 {
		log.Printf("[WARNING] Potential attack detected from %s (%d connection attempts)",
			conn.SourceIP, sm.suspiciousIPs[conn.SourceIP])
	}
}

// SimulateNetworkMonitoring simulates monitoring network connections
func (sm *SecurityMonitor) SimulateNetworkMonitoring() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Check active connections using 'netstat' or similar commands
	for range ticker.C {
		sm.checkActiveConnections()
	}
}

func (sm *SecurityMonitor) checkActiveConnections() {
	// On Linux, we would use netstat or ss to get active connections
	// This is a simulated version that parses netstat output
	cmd := exec.Command("netstat", "-tuna")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Failed to get active connections: %v", err)

		// Let's simulate some activity for the demo
		sm.simulateConnectionActivity()
		return
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Skip header lines and empty lines
		if !strings.Contains(line, "ESTABLISHED") && !strings.Contains(line, "SYN_SENT") {
			continue
		}

		// Parse connection information (simplified)
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		localParts := strings.Split(parts[3], ":")
		remoteParts := strings.Split(parts[4], ":")
		if len(localParts) < 2 || len(remoteParts) < 2 {
			continue
		}

		// Check if this connection is to a monitored port
		destPort, _ := strconv.ParseUint(remoteParts[len(remoteParts)-1], 10, 16)
		if sm.monitoredPorts[uint16(destPort)] {
			// This is a connection to a monitored port
			sm.AddSuspiciousConnection(ConnectionAttempt{
				SourceIP:   localParts[0],
				DestIP:     remoteParts[0],
				DestPort:   uint16(destPort),
				Timestamp:  time.Now(),
				Suspicious: true,
			})
		}
	}
}

// simulateConnectionActivity simulates network activity for demonstration
func (sm *SecurityMonitor) simulateConnectionActivity() {
	// Random ports to simulate connection attempts
	ports := []uint16{22, 80, 443, 3389, 445, 1433, 3306}

	// Simulate 1-3 connection attempts
	numAttempts := 1 + time.Now().UnixNano()%3
	for i := int64(0); i < numAttempts; i++ {
		// Generate a random connection
		srcIP := fmt.Sprintf("192.168.1.%d", 100+time.Now().UnixNano()%100)
		dstIP := "10.0.0.5"
		dstPort := ports[time.Now().UnixNano()%int64(len(ports))]

		// Add the connection if it's to a monitored port
		if sm.monitoredPorts[dstPort] {
			sm.AddSuspiciousConnection(ConnectionAttempt{
				SourceIP:    srcIP,
				SourcePort:  uint16(30000 + time.Now().UnixNano()%10000),
				DestIP:      dstIP,
				DestPort:    dstPort,
				Timestamp:   time.Now(),
				ProcessName: "simulation",
				Suspicious:  true,
			})
		}
	}
}

// PrintStatistics prints monitoring statistics
func (sm *SecurityMonitor) PrintStatistics() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	fmt.Println("\n=== Security Monitoring Statistics ===")
	fmt.Printf("Total suspicious connections: %d\n", len(sm.connections))
	fmt.Printf("Unique suspicious source IPs: %d\n", len(sm.suspiciousIPs))

	// Print top offenders
	fmt.Println("\nTop suspicious IPs:")
	count := 0
	for ip, attempts := range sm.suspiciousIPs {
		fmt.Printf("  - %s: %d attempts\n", ip, attempts)
		count++
		if count >= 5 {
			break
		}
	}
	fmt.Println("=======================================")
}

func main() {
	// Set up logging
	log.SetPrefix("[Security Monitor] ")

	// Remove resource limits for eBPF (needed for real eBPF applications)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Warning: Failed to remove memory lock: %v", err)
	}

	log.Println("Starting eBPF Security Monitoring")
	log.Println("Monitoring for suspicious connection attempts...")

	// Create security monitor
	monitor := NewSecurityMonitor()

	// Create a minimal eBPF map to demonstrate functionality
	mapSpec := &ebpf.MapSpec{
		Name:       "connection_tracking",
		Type:       ebpf.Hash,
		KeySize:    8, // IP address (4) + port (2) + padding (2)
		ValueSize:  8, // Timestamp (8)
		MaxEntries: 1024,
	}

	trackingMap, err := ebpf.NewMap(mapSpec)
	if err != nil {
		log.Printf("Warning: Failed to create eBPF map: %v", err)
	} else {
		defer trackingMap.Close()
		log.Println("Successfully created connection tracking map")
	}

	// Start simulated network monitoring in background
	go monitor.SimulateNetworkMonitoring()

	// Print statistics periodically
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			monitor.PrintStatistics()
		}
	}()

	// Set up signal handler for clean exit	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\nShutting down security monitor...")
	monitor.PrintStatistics()
}
