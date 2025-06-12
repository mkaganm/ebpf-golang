//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang PortMonitor ebpf/port_monitor.c -- -I/usr/include -I./ebpf/bpf -D__KERNEL__

type eventT struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

func ipToString(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("rlimit: %v", err)
	}

	ifaceName := "eth0"
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface: %v", err)
	}

	objs := PortMonitorObjects{}
	if err := LoadPortMonitorObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.MonitorPort,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attach xdp: %v", err)
	}
	defer lnk.Close()

	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rb.Close()
	log.Printf("Monitoring SSH port (22) connections... (interface: %s)", ifaceName)
	log.Printf("Press Ctrl+C to exit")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nShutting down...")
		rb.Close()
		lnk.Close()
		objs.Close()
		os.Exit(0)
	}()

	for {
		record, err := rb.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				break
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}
		var evt eventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("decode: %v", err)
			continue
		}
		log.Printf("SSH connection attempt: %s:%d -> %s:%d", ipToString(evt.SrcIP), evt.SrcPort, ipToString(evt.DstIP), evt.DstPort)
	}
}
