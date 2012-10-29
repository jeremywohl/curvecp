package main

// CurveCP creates a reliable, encrypted stream between authenticated parties.

import (
	"net"
	"fmt"
)

func main() {
	addr := &net.UDPAddr{ net.ParseIP("127.0.0.1"), 1034 }
	conn, _ := net.ListenUDP("udp", addr)
	
	b := make([]byte, 1400)
	count, err := conn.Read(b)
	
	fmt.Printf("count: %d, err: %v, packet: %s\n", count, err, string(b))
}