package curvecp

import (
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"net"
	"fmt"
	"time"
	"bytes"
	"encoding/binary"
	"list"
)

const minUDPPacketLength = 64
const maxUDPPacketLength = 1184
const helloPacketLength  = 224
const cookiePacketLength = 200

const (
	packetGood    = '-'
	packetDiscard = 'd'
)

type packetKind struct {
	magic []byte
	marker byte
}

var kindHello          = packetKind{ magic: []byte("QvnQ5XlH"), marker: 'H' }
var kindCookie         = packetKind{ magic: []byte("RL3aNMXK"), marker: 'C' }
var kindInitiate       = packetKind{ magic: []byte("QvnQ5XlI"), marker: 'I' }
var kindServerMessage  = packetKind{ magic: []byte("RL3aNMXM"), marker: 'S' }
var kindClientMessage  = packetKind{ magic: []byte("QvnQ5XlM"), marker: 'C' }
var kindUnknown        = packetKind{ magic: []byte(""),         marker: '?' }

type helloPacket struct {
	sext          [16]byte  // server extension
	cext          [16]byte  // client extension
	cEphPublicKey [32]byte  // client ephemeral (short-term) public key
	padding       [64]byte
	nonce         [8]byte
	box           [80]byte
}

func debug(packetLength, payloadLength int, ajudication byte, kind packetKind) {
	var l string
	
	switch packetLength {
	case -1:
		l = "++++"
	case -2:
		l = "----"
	default:
		l = string(packetLength)
	}
	
	t := time.Now()
	
	fmt.Printf("%d.%9d %c %c %4s\n", t.Unix(), t.Nanosecond(), kind.marker, ajudication, l)
}

type CurveCPConn struct {
	listener *CurveCPListener
	conn *net.UDPConn
	
	start time.Time
	debug bool
	
	// ephemeral (short-term) key pair
	ephPublicKey  *[32]byte
	ephPrivateKey *[32]byte
	
	// read/write buffer
}

type CurveCPListener struct {
	connections map[[]byte]*net.UDPConn
	
	backlog chan *CurveCPConn
	backlogSize int
	
	minuteKey [32]byte      // a secret key refreshed once a minute
	lastMinuteKey [32]byte  // allow 120-second response lags from Cookie packets
	lastKeyRefresh time.Time
	// TODO: []clientKeysSeen closed conn cache per minuteKey -- structure as a sub-struct?

	closing chan bool
}

func ListenCurveCP(net string, addr *net.UDPAddr) (l *CurveCPListener, err error) {
	l = new(CurveCPListener)

	l.backlogSize = 5
 	l.backlog = make(chan *CurveCPConn, l.backlogSize)

	l.closing = make(chan bool)
	
	err = rand.Read(l.minuteKey)
	if err != nil {
		return err
	}
	err = rand.Read(l.lastMinuteKey)  // randomize while unused in first 60 seconds
	if err != nil {
		return err
	}
	lastKeyRefresh = time.Now()
	
	l.conn, err = net.ListenUDP(net, addr)
	if err != nil {
		return nil, err
	}
	
	go l.reactor()
	
	return c, nil
}

func (l *CurveCPListener) Accept() (c *CurveCPConn, err error) {
	select {
	case c <- l.backlog:
		return c, nil
	case <- quit:
		return nil, nil  // TODO: appropriate error code?
	}
}

func (l *CurveCPListener) Close() {
	l.closing <- true
	
	// TODO: notify backlog clients
	// ... ?
}

func (l *CurveCPListener) reactor() {
	// respond to Hello's
	// respond to Initiate with an empty Message packet and return to caller
	// respond to ClientMessage's

	for {
		var buff [1400]byte
		bytesRead, _, _ := c.conn.ReadFromUDP(buff[:])

		if bytesRead > maxUDPPacketLength {
			debug(-1, -1, packetDiscard, kindUnknown)
			// return ...
		}
	
		if bytesRead < minUDPPacketLength {
			debug(-2, -1, packetDiscard, kindUnknown)
		}
	
		magic := buff[:8]
	
		if bytes.Equal(magic, kindHello.magic) && bytesRead == helloPacketLength {
			readHello(buff[:helloPacketLength])
		} else if bytes.Equal(magic, kindInitiate.magic) {
			readInitiate(buff[:maxUDPPacketLength])
		} else if bytes.Equal(magic, kindClientMessage.magic) {
			readClientMessage(buff[:maxUDPPacketLength])
		} else {
		
		}
	}

	
	c.ephPublicKey, c.ephPrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	
	
}

func Dial(addr *net.UDPAddr) (c * CurveCPConn, err error) {
	c = new(CurveConn)
	
	c.conn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	
	return c, nil
}
	
func (c *CurveCPConn) Read(b []byte) (err error) {
	for ;; {
		var buff [1400]byte
		bytesRead, _, _ := c.conn.ReadFromUDP(buff[:])

		if bytesRead > maxUDPPacketLength {
			debug(-1, -1, packetDiscard, kindUnknown)
			// return ...
		}
		
		if bytesRead < minUDPPacketLength {
			debug(-2, -1, packetDiscard, kindUnknown)
		}
		
		magic := buff[:8]
		
		if bytes.Equal(magic, kindHello.magic) && bytesRead == helloPacketLength {
			readHello(buff[:helloPacketLength])
		} else if bytes.Equal(magic, kindInitiate.magic) {
			readInitiate(buff[:maxUDPPacketLength])
		} else if bytes.Equal(magic, kindClientMessage.magic) {
			readClientMessage(buff[:maxUDPPacketLength])
		} else {
			
		}
	}
	
	return nil
}

func readHello(buff []byte) (err error) {
	var pckt helloPacket
	
	p := bytes.NewBuffer(buff)
	
	err = binary.Read(p, binary.LittleEndian, &pckt)
	
	if err != nil {
		return err
	}
	
	fmt.Println("hi")
	
	return nil
}

func readInitiate(buff []byte) { }
func readClientMessage(buff []byte) { }

func (c *CurveCPConn) Write() (count int) {
	b := make([]byte, 2000)

	for i := 0; i < 2; i++ {
		count, _ = c.conn.Write(b)
	}
	
	return count
}
