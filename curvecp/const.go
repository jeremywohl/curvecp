package curvecp

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
