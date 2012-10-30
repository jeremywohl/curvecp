package main

import (
	"net"
	"fmt"
	"./curvecp"
)

func main() {
	addr := &net.UDPAddr{ net.ParseIP("127.0.0.1"), 1034 }
	conn, _ := curvecp.Dial(addr)
	count := conn.Write()
	
	fmt.Printf("count: %d\n", count)
}