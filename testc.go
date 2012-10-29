package main

import (
	"net"
	"fmt"
)

func main() {
	addr := &net.UDPAddr{ net.ParseIP("127.0.0.1"), 1034 }
	conn, _ := net.DialUDP("udp", nil, addr)
	
	count, _ := conn.Write([]byte{'a','b','c'})
	
	fmt.Printf("count: %d\n", count)
}