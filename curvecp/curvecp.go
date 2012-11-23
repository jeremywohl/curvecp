package curvecp

// Working on:
//  Parsing Hello packets
//  updating minute keys (after every packet), what logic to diff keys

// TODO: DialImmediateConnect



const (
	pendingPhase = iota
	helloPhase
	initiatePhase
	connected
)
