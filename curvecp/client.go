package curvecp

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"list"
	"net"
	"time"
)

// The connection is lazily established, letting data be included in the handshake.
// A subsequent Read() or Write() may fail establishing a connection.
func Dial(addr *net.UDPAddr) (c *CurveCPConn, err error) {
	c = new(CurveConn)
	
	connectTimeout = c.TimeAfter() // min (60s or deadline)

	c.ephPublicKey, c.ephPrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	c.nonce = rand.Int63n(1<<48) // start incrementing at random [0,2^48)
	
	c.conn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	// send hello and start one second timer
	// for {}
	// select on helloRepeatTimer, connect deadline, cookie packet, 60-second overall deadline
	
	for {
		select {
			case <-time.After(min(c.deadline, time.Minute)) // connection timeout
		}
	}

	go c.clientReactor()

	return c, nil
}

func DialWithUnauthenticatedServer() {}
func DialWithServerKey() {}

func (l *CurveCPListener) clientReactor() {
	for {
		var buff [1400]byte

		bytesRead, raddr, _ := l.conn.ReadFromUDP(buff[:])

		if bytesRead > maxUDPPayload {
			debug(-1, -1, packetDiscard, kindUnknown)
			continue
		}

		if bytesRead < minUDPPayload {
			debug(-2, -1, packetDiscard, kindUnknown)
			continue
		}

		switch {
		case bytes.HasPrefix(buff, kindServerMessage.magic):
			processServerMessage(buff[8:bytesRead], raddr)
		case bytes.HasPrefix(buff, kindCookie.magic) && bytesRead == cookiePacketLength:
			processCookie(buff[8:bytesRead], raddr)
		default:
			debug(dirIncoming, bytesRead, -1, packetDiscard, kindUnknown)
			continue
		}
	}
}

func (c *CurveCPConn) Read(b []byte) (err error) {
	if !c.client.sentHello {
		c.sendHello()
	}

	return nil
}

func (c *CurveCPConn) sendHello() (err error) {
	// lookup server's long-term key
	var packet    [224]byte
	var zeroBytes [64]byte
	var nonce     [24]byte
	
	copy(packet[:], helloPkt.magic)
	copy(packet[8:], zeroBytes[0:16])
	copy(packet[24:], zeroBytes[0:16])
	copy(packet[40:], c.ephPublicKey)
	copy(packet[72:], zeroBytes)
	
	copy(nonce[:], helloPkt.noncePrefix)
	randomnonce(nonce[16:])
	
	copy(packet[136:], nonce[16:])
	box.
}

func readInitiate(buff []byte)      {}
func readClientMessage(buff []byte) {}

func (c *CurveCPConn) Write() (count int) {
	b := make([]byte, 2000)

	for i := 0; i < 2; i++ {
		count, _ = c.conn.Write(b)
	}

	return count
}

func (c *CurveCPConn) Close() error {
	var zeroBytes [32]byte
	
	copy(*c.ephPrivateKey, zeroBytes)
	copy(*c.ephPublicKey, zeroBytes)
	copy(*c.sharedKey, zeroBytes)
}

