package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@latest -go-package main packetcount ebpf/packet_count.c -- -I/usr/include -Iebpf

func main() {
	objs := packetcountObjects{}
	if err := loadPacketcountObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: 2, // 2 might be for eth0, check with ip link
	})
	if err != nil {
		panic(err)
	}
	defer l.Close()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Counting packets... Press Ctrl+C to exit")
	<-sig

	var key uint32 = 0
	var value uint64
	if err := objs.PacketCount.Lookup(&key, &value); err != nil {
		panic(err)
	}
	fmt.Printf("Total packets: %d\n", value)
}
