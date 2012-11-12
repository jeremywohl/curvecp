package curvecp

// Working on:
//  Parsing Hello packets
//  updating minute keys (after every packet), what logic to diff keys
//  consider packet consumption as channel, so timers can go on select

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

const minUDPPayload      = 64
const maxUDPPayload      = 1184
const helloPacketLength  = 224
const cookiePacketLength = 200
const backlogDefaultSize = 128
const dirIncoming        = 1
const dirOutgoing        = 2

const (
	packetGood    = '-'
	packetDiscard = 'd'
)

const (
	nonceHelloPrefix         = "CurveCP-client-H"
	nonceCookiePrefix        = "CurveCPK"
	nonceInitiatePrefix      = "CurveCP-client-I"
	nonceInitiatecPrefix     = "CurveCPV"
	nonceServerMessagePrefix = "CurveCP-server-M"
	nonceClientMessagePrefix = "CurveCP-client-M"
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

func debug(direction, packetLength, payloadLength int, ajudication byte, kind packetKind) {
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
	
	conn *net.UDPConn
	
	backlog chan *CurveCPConn
	backlogSize int
	
	minuteKey [32]byte      // a secret key refreshed once a minute
	priorMinuteKey [32]byte  // allow 120-second response lags from Cookie packets
	minuteTicker *time.Ticker
	minuteMutex sync.Mutex
	// TODO: []clientKeysSeen closed conn cache per minuteKey -- structure as a sub-struct?

	packets chan 
	closing chan bool
}

func ListenCurveCP(net string, addr *net.UDPAddr) (l *CurveCPListener, err error) {
	l = new(CurveCPListener)

	if l.backlogSize == 0 {
		l.backlogSize = backlogDefaultSize
	}
 	l.backlog = make(chan *CurveCPConn, l.backlogSize)

	l.closing = make(chan bool)
	
	l.updateMinuteKeysOnce()  // scramble both minutes
	l.updateMinuteKeysOnce()
	
	l.conn, err = net.ListenUDP(net, addr)
	if err != nil {
		return nil, err
	}
	
	go l.reactor()

	l.minuteTicker = time.NewTicker(time.Minute)
	go l.updateMinuteKeys()
	
	return c, nil
}

func (l *CurveCPListener) Accept() (c *CurveCPConn, err error) {
	select {
	case c = <- l.backlog:
		return c, nil
	case <- l.closing:
		return nil, nil  // TODO: appropriate error code?
	}
}

func (l *CurveCPListener) Close() {
	l.closing <- true
	l.minuteTicker.Stop()
	
	// TODO: notify backlog clients
	// ... ?
}

func (l *CurveCPListener) reactor() {
	// respond to Hello's
	// respond to Initiate with an empty Message packet and return to caller
	// respond to ClientMessage's
	// since we need to react to a number of timing signals, might be better to use a goroutine to
	//  to channel packets, then select on that and various timers

	for {
		var buff [1400]byte

		bytesRead, _, _ := c.conn.ReadFromUDP(buff[:])

		if bytesRead > maxUDPPayload {
			debug(-1, -1, packetDiscard, kindUnknown)
			continue
		}
	
		if bytesRead < minUDPPayload {
			debug(-2, -1, packetDiscard, kindUnknown)
			continue
		}
	
		magic := buff[:8]
	
		if bytes.Equal(magic, kindClientMessage.magic) {
			processClientMessage(buff[8:bytesRead])
		} else if bytes.Equal(magic, kindHello.magic) && bytesRead == helloPacketLength {
			processHello(buff[8:bytesRead])
		} else if bytes.Equal(magic, kindInitiate.magic) {
			processInitiate(buff[8:bytesRead])
		} else {
			debug(dirIncoming, bytesRead, -1, packetDiscard, kindUnknown)
			continue
		}
	}
}

func processHello(buff []byte) (err error) {
	if len(buff) != helloPacketLength {
		// discard
	}
	
	var sext, cext    [16]byte
	var cEphPublicKey [32]byte
	var nonce         [24]byte
	var box           [80]byte
	var data          [64]byte
	
	copy(sext,          buff[0:16])
	copy(cext,          buff[16:32])
	copy(cEphPublicKey, buff[32:64])
	copy(nonce,         []byte("CurveCP-client-H"))
	copy(nonce[16:24],  buff[128:136])
	
	data, ok := box.Open(nil, buff[136:], &nonce, l.sPublicKey, cEphPublicKey)
	if ok == false {
		// discard
	}
	
	// QQQ: do we need to verify encrypted data is all zeroes?
	
	// send Cookie packet

	sEphPublicKey, sEphPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic()
	}
	
	var cookieBuff [200]byte
	var kookieData [96]byte
	var nonce2     [24]byte
	var data2      [128]byte
	
	copy(cookieBuff,       kindCookie.magic)
	copy(cookieBuff[8:],   sext)
	copy(cookieBuff[24:],  cext)
	randomnonce(cookieBuff[40:56])
	copy(kookieData[:],    cEphPublicKey)
	copy(kookieData[32:],  sEphPrivateKey)
	copy(nonce2,           []byte("minute-k"))
	randomnonce(nonce2[16:])
	secretbox.Seal(buff[56:], kookieData, &nonce2, &l.minuteKey)
	copy(data2,            )
	
	
	return nil
}

func randomnonce(b []byte) {
	if err := rand.Read(b); err != nil {
		panic()
	}
}

func (l *CurveCPListener) updateMinuteKeys() {
	for range l.minuteTicker.C {
		l.updateMinuteKeysOnce()
	}
}

func (l *CurveCPListener) updateMinuteKeysOnce() {
	minuteMutex.Lock()
	defer minuteMutex.unLock()
	
	copy(l.priorMinuteKey, l.minuteKey)

	err := rand.Read(l.minuteKey)
	if err != nil {
		panic()  // TODO: alternatively, stop accepting connections temporarily
	}
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

func Dial(addr *net.UDPAddr) (c * CurveCPConn, err error) {
	c = new(CurveConn)
	
	c.conn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	
	return c, nil
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
