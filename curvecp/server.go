package curvecp

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

type CurveCPConn struct {
	listener *CurveCPListener
	conn     *net.UDPConn

	start time.Time
	debug bool

	// ephemeral (short-term) key pair
	ephPublicKey  *[32]byte
	ephPrivateKey *[32]byte

	sharedKey     *[32]byte
	
	// read/write buffer
	
	client   *curveCPClient
	
	nonce int64
}

type CurveCPListener struct {
	connections map[[32]byte]*net.UDPConn

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
		helloSharedKey [32]byte // only used in these Hello and Cookie packets (C', s)
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
	copy(nonce,           []byte("boomerng"))
	randomnonce(nonce[8:])
	copy(cookieBuff[56:], nonce[8:])

	minuteMutex.Lock()
	secretbox.Seal(cookieBuff[56:], kookieData, &nonce, &l.minuteKey)
	minuteMutex.unLock()

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
