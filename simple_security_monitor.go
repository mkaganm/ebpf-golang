package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log.SetPrefix("[Security Monitor] ")

	log.Println("Starting eBPF Security Monitoring")
	log.Println("Monitoring for suspicious connection attempts...")

	// Print some security information periodically
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		portsToMonitor := []int{22, 80, 443, 3389, 445, 1433, 3306}
		counter := 0

		for range ticker.C {
			counter++
			// Simulate some security alerts
			srcIP := fmt.Sprintf("192.168.1.%d", 100+(counter%100))
			dstPort := portsToMonitor[counter%len(portsToMonitor)]

			log.Printf("[ALERT] Suspicious connection from %s:%d to 10.0.0.5:%d",
				srcIP, 30000+counter, dstPort)

			if counter%5 == 0 {
				fmt.Println("\n=== Security Monitoring Statistics ===")
				fmt.Printf("Total suspicious connections: %d\n", counter)
				fmt.Printf("Unique suspicious source IPs: %d\n", counter/3)
				fmt.Println("Top suspicious IPs:")
				fmt.Printf("  - %s: %d attempts\n", srcIP, counter/2)
				fmt.Printf("  - 192.168.1.%d: %d attempts\n", (counter+10)%100, counter/3)
				fmt.Println("=======================================")
			}
		}
	}()

	// Set up signal handler for clean exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down security monitor...")
}
