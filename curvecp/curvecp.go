package curvecp

// Working on:
//  Parsing Hello packets
//  updating minute keys (after every packet), what logic to diff keys
//  consider packet consumption as channel, so timers can go on select

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

const (
	minUDPPayload      = 64
	maxUDPPayload      = 1184
	helloPacketLength  = 224
	cookiePacketLength = 200
	backlogDefaultSize = 128
	dirIncoming        = 1
	dirOutgoing        = 2
)

const (
	packetGood    = '-'
	packetDiscard = 'd'
)

type kindOfPacket struct {
	magic, noncePrefix []byte
	marker             byte
}

var (
	helloPkt         = kindOfPacket{marker: 'H', magic: []byte("QvnQ5XlH"), noncePrefix: []byte("CurveCP-client-H")}
	cookiePkt        = kindOfPacket{marker: 'C', magic: []byte("RL3aNMXK"), noncePrefix: []byte("CurveCPK")}
	inititatePkt     = kindOfPacket{marker: 'I', magic: []byte("QvnQ5XlI"), noncePrefix: []byte("CurveCP-client-I")}
	serverMessagePkt = kindOfPacket{marker: 'S', magic: []byte("RL3aNMXM"), noncePrefix: []byte("CurveCPV")}
	clientMessagePkt = kindOfPacket{marker: 'C', magic: []byte("QvnQ5XlM"), noncePrefix: []byte("CurveCP-client-M")}
	unknownPkt       = kindOfPacket{marker: '?', magic: []byte("")}
)

type helloPacket struct {
	sext          [16]byte // server extension
	cext          [16]byte // client extension
	cEphPublicKey [32]byte // client ephemeral (short-term) public key
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
	conn     *net.UDPConn

	start time.Time
	debug bool

	// ephemeral (short-term) key pair
	ephPublicKey  *[32]byte
	ephPrivateKey *[32]byte

	sharedKey *[32]byte

	// read/write buffer
}

type CurveCPListener struct {
	connections map[[]byte]*net.UDPConn

	conn *net.UDPConn

	backlog     chan *CurveCPConn
	backlogSize int

	minuteKey      [32]byte // a secret key refreshed once a minute
	priorMinuteKey [32]byte // allow 120-second response lag from Cookie packets
	minuteTicker   *time.Ticker
	minuteMutex    sync.Mutex
	// TODO: []clientKeysSeen closed conn cache per minuteKey -- structure as a sub-struct?

	closing chan bool
}

func ListenCurveCP(net string, addr *net.UDPAddr) (l *CurveCPListener, err error) {
	l = new(CurveCPListener)

	if l.backlogSize == 0 {
		l.backlogSize = backlogDefaultSize
	}
	l.backlog = make(chan *CurveCPConn, l.backlogSize)

	l.closing = make(chan bool)

	l.updateMinuteKeysOnce() // scramble both minutes
	l.updateMinuteKeysOnce()

	l.conn, err = net.ListenUDP(net, addr)
	if err != nil {
		return nil, err
	}

	go l.serverReactor()

	l.minuteTicker = time.NewTicker(time.Minute)
	go l.updateMinuteKeys()

	return c, nil
}

func (l *CurveCPListener) Accept() (c *CurveCPConn, err error) {
	select {
	case c = <-l.backlog:
		return c, nil
	case <-l.closing:
		return nil, nil // TODO: appropriate error code?
	}
}

func (l *CurveCPListener) Close() {
	l.closing <- true
	l.minuteTicker.Stop()

	// TODO: notify backlog clients
	// ... ?
}

func (l *CurveCPListener) serverReactor() {
	// respond to Hello's
	// respond to Initiate with an empty Message packet and return to caller
	// respond to ClientMessage's
	// since we need to react to a number of timing signals, might be better to use a goroutine to
	//  to channel packets, then select on that and various timers

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
		case bytes.HasPrefix(buff, kindClientMessage.magic):
			processClientMessage(buff[8:bytesRead], raddr)
		case bytes.HasPrefix(buff, kindHello.magic) && bytesRead == helloPacketLength:
			processHello(buff[8:bytesRead], raddr)
		case bytes.HasPrefix(buff, kindInitiate.magic):
			processInitiate(buff[8:bytesRead], raddr)
		default:
			debug(dirIncoming, bytesRead, -1, packetDiscard, kindUnknown)
			continue
		}
	}
}

func processHello(buff []byte, raddr *UDPAddr) (err error) {
	if len(buff) != helloPacketLength {
		// discard
	}

	var (
		sext, cext     [16]byte
		cEphPublicKey  [32]byte
		helloSharedKey [32]byte // only used in these two packets (C', s)
		nonce          [24]byte
		box            [80]byte
		data           [64]byte
	)

	copy(sext,          buff[0:16])
	copy(cext,          buff[16:32])
	copy(cEphPublicKey, buff[32:64])
	copy(nonce,         helloPkt.noncePrefix)
	copy(nonce[16:24],  buff[128:136])

	box.Precompute(&helloSharedKey, &cEphPublicKey, &sPrivateKey)

	data, ok := box.OpenAfterPrecomputation(nil, buff[136:], &nonce, &helloSharedKey)
	if ok == false {
		// discard
	}

	// Q: do we need to verify encrypted data is all zeroes?

	// send Cookie packet

	sEphPublicKey, sEphPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic()
	}

	var (
		cookieBuff [200]byte
		kookieData [96]byte
		data2      [128]byte
	)

	copy(kookieData[:],   cEphPublicKey)
	copy(kookieData[32:], sEphPrivateKey)
	copy(nonce,           []byte("backtome"))
	randomnonce(nonce[8:])
	copy(cookieBuff[56:], nonce[8:])
	secretbox.Seal(cookieBuff[56:], kookieData, &nonce, &l.minuteKey)

	copy(cookieBuff,        cookiePkt.magic)
	copy(cookieBuff[8:],    sext)
	copy(cookieBuff[24:],   cext)
	copy(nonce,             cookiePkt.noncePrefix)
	randomnonce(nonce[8:])
	copy(cookieBuff[40:56], nonce[8:])
	copy(data2[:],          sEphPublicKey)
	copy(data2[32:],        kookieData)
	box.SealAfterPrecomputation(cookieBuff[56:], data2, &nonce, &helloSharedKey)

	_, err := l.conn.WriteToUDP(cookieBuff, raddr)
	if err != nil {
		panic()
	}

	return nil
}

func randomnonce(b []byte) {
	if err := rand.Read(b); err != nil {
		panic()
	}
}

func (l *CurveCPListener) updateMinuteKeys() {
	for _ := range l.minuteTicker.C {
		l.updateMinuteKeysOnce()
	}
}

func (l *CurveCPListener) updateMinuteKeysOnce() {
	minuteMutex.Lock()
	defer minuteMutex.unLock()

	copy(l.priorMinuteKey, l.minuteKey)

	err := rand.Read(l.minuteKey)
	if err != nil {
		panic() // TODO: alternatively, stop accepting connections temporarily
	}
}

// The connection is lazily established during the first Read() or Write() to allow data to be
// included in the handshake.
func Dial(addr *net.UDPAddr) (c *CurveCPConn, err error) {
	c = new(CurveConn)

	c.ephPublicKey, c.ephPrivateKey, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	c.conn, err = net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	go c.clientReactor()

	return c, nil
}

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

	return nil
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
