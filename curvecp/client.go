package curvecp

import (
	"math/big"
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	//"encoding/binary"
	//"fmt"
	"net"
	"time"
)

// temporary variables used during connection setup
type curveCPClient struct {
	serverCookie   [96]byte
	sharedHelloKey [32]byte
	sharedVouchKey [32]byte
}

// The connection is lazily established, letting data be included in the handshake.
// A subsequent Read() or Write() may fail establishing a connection.
func Dial(addr *net.UDPAddr) (c *CurveCPConn, err error) {
	c = new(CurveCPConn)
	c.client = new(curveCPClient)
	
	c.ephPublicKey, c.ephPrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// TODO: fetch server and client long-term keys
	var sPublicKey [32]byte
	var cPrivateKey [32]byte
	
	box.Precompute(&c.client.sharedHelloKey, &sPublicKey, c.ephPrivateKey)
	box.Precompute(&c.client.sharedVouchKey, &sPublicKey, &cPrivateKey)
	
	nonceInt, err := rand.Int(rand.Reader, big.NewInt(1<<48)) // start incrementing at random [0,2^48)
	if err != nil {
		return nil, err
	}
	c.nonce = nonceInt.Int64()
	
	c.conn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	c.sendHello()
	deadline := 1000 // TODO: add to connection struct
	connectionTimeout := time.NewTimer(min(deadline, 60 * time.Second))

	cookies := make(chan bool)
	go c.cookieReceiver(cookies)
	
	for {
		select {
		case <-cookies:
			break
		case <-time.After(time.Second): // repeat Hello; TODO: fuzz + backoff
			c.sendHello()
		case <-connectionTimeout.C:
			return nil, ConnectionTimeoutError
		}
	}

	go c.clientReactor()

	return c, nil
}

func DialWithUnauthenticatedServer() {}
func DialWithServerKey() {}

func (c *CurveCPConn) cookieReceiver(ch chan bool) {
	for {
		var buff [1400]byte

		bytesRead, err := c.conn.Read(buff[:])
		if err != nil {
			// TODO: debug
			continue
		}

		if bytesRead != cookiePacketLength {
			debug(-1, -1, packetDiscard, 'd', unknownPkt)
			continue
		}

		if !bytes.HasPrefix(buff[:], cookiePkt.magic) {
			debug()
			continue
		}

		var text [128]byte
		var nonce [24]byte
		var sEphPublicKey [32]byte
		
		copy(nonce, cookiePkt.noncePrefix)
		copy(nonce[8:], packet[40:56])
		_, ok := box.OpenAfterPrecomputation(text, packet[56:], &nonce, &c.client.sharedHelloKey)
		if ok == false {
			debug(-1, -1, packetDiscard, 'd', unknownPkt)
			continue
		}

		copy(sEphPublicKey, text[0:32])
		box.Precompute(&c.sharedKey, &sEphPublicKey, &c.ephPrivateKey)
		copy(c.client.serverCookie, text[32:])

		ch <-true
		break
	}
}

func (c *CurveCPConn) clientReactor() {
	for {
		var buff [1400]byte

		bytesRead, _ := l.conn.Read(buff[:])

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
			processServerMessage(buff[8:bytesRead])
		case bytes.HasPrefix(buff, kindCookie.magic) && bytesRead == cookiePacketLength:
			processCookie(buff[8:bytesRead])
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

func (c *CurveCPConn) sendHello() error {
	// TODO: lookup server's long-term key
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
	box.SealAfterPrecomputation(packet[144:], zeroBytes, &nonce, &c.client.sharedHelloKey)
	
	_, err := l.conn.Write(packet)
	return err
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

