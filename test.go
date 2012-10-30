package main

// CurveCP creates a reliable, encrypted stream between authenticated parties.

import (
	// "code.google.com/p/go.crypto/nacl/box"
	// "crypto/rand"
	"net"
	"fmt"
	"./curvecp"
)

func main() {
	fmt.Println("start")
	
	addr := &net.UDPAddr{ net.ParseIP("127.0.0.1"), 1034 }
	conn, _ := curvecp.Listen(addr)
	
	var b [1088]byte
	conn.Read(b[:])
}
