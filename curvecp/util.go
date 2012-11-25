func randomnonce(b []byte) {
	if err := rand.Read(b); err != nil {
		panic()
	}
}

// randomly add up to 30%
func randomfuzz(in int64) int64 {
	
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

func min(x, y int) (r int) {
	if x < y {
		return x
	}
	
	return y
}
