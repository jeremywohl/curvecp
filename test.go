package main

// CurveCP creates a reliable, encrypted stream between authenticated parties.

import (
	// "code.google.com/p/go.crypto/nacl/box"
	// "crypto/rand"
	"net"
	"fmt"
)

func main() {
	// pub, priv, _ := box.GenerateKey(rand.Reader)
	// fmt.Println(pub)
	// fmt.Println(priv)
	addr := &net.UDPAddr{ net.ParseIP("127.0.0.1"), 1034 }
	conn, _ := net.ListenUDP("udp", addr)
	
	b := make([]byte, 1400)
	count, err := conn.Read(b)
	
	fmt.Printf("count: %d, err: %v, packet: %s\n", count, err, string(b))
}
