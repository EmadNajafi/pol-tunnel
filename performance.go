package main

import (
	"fmt"
	"strings"
	"time"
)

// Performance profiles: one word that fills in every tuning value at once
// (like BackPack's presets). A key written explicitly in the config always
// wins over the profile. A config with no `performance` key behaves exactly
// as before — that is "balance".
//
//	balance     light on CPU and RAM; small or shared servers (the default)
//	turbo       larger mux windows and a quicker ARQ; the usual choice
//	aggressive  big windows, more connections, pushes hard through loss;
//	            uses noticeably more RAM and CPU
//	throughput  bulk transfer: the largest windows, batched ACKs, Nagle on;
//	            not for games or interactive traffic
//
// Each side tunes itself (windows are advertised on the wire), so the two ends
// do not have to match — but using the same profile on both is the sane setup,
// since each direction is paced by the receiver's window.
type perfProfile struct {
	MuxWindow    int
	MuxFrameSize int
	Nodelay      bool
	ChannelSize  int
	Pool         int // client: connection_pool

	// spoof / spoofmux (ARQ)
	ARQWindow   int // receive window and send queue, in 1200-byte segments
	ARQInitCwnd int
	ARQFloor    int
	ARQFastRes  int
	ARQMinRTO   time.Duration
	ARQInterval time.Duration
	ARQDelayAck bool
}

var perfProfiles = map[string]perfProfile{
	"balance": {
		MuxWindow: 512 * 1024, MuxFrameSize: 32 * 1024, Nodelay: true, ChannelSize: 2048, Pool: 8,
		ARQWindow: 1024, ARQInitCwnd: 32, ARQFloor: 8, ARQFastRes: 3,
		ARQMinRTO: 50 * time.Millisecond, ARQInterval: 10 * time.Millisecond,
	},
	"turbo": {
		MuxWindow: 2 * 1024 * 1024, MuxFrameSize: 32 * 1024, Nodelay: true, ChannelSize: 2048, Pool: 8,
		ARQWindow: 1024, ARQInitCwnd: 64, ARQFloor: 16, ARQFastRes: 2,
		ARQMinRTO: 30 * time.Millisecond, ARQInterval: 10 * time.Millisecond,
	},
	"aggressive": {
		MuxWindow: 8 * 1024 * 1024, MuxFrameSize: 32 * 1024, Nodelay: true, ChannelSize: 4096, Pool: 16,
		ARQWindow: 2048, ARQInitCwnd: 128, ARQFloor: 64, ARQFastRes: 2,
		ARQMinRTO: 30 * time.Millisecond, ARQInterval: 10 * time.Millisecond,
	},
	"throughput": {
		MuxWindow: 16 * 1024 * 1024, MuxFrameSize: 65535, Nodelay: false, ChannelSize: 4096, Pool: 8,
		ARQWindow: 4096, ARQInitCwnd: 128, ARQFloor: 32, ARQFastRes: 3,
		ARQMinRTO: 50 * time.Millisecond, ARQInterval: 20 * time.Millisecond, ARQDelayAck: true,
	},
}

const perfNames = "balance, turbo, aggressive, throughput"

// perfFor returns the profile for name ("" = balance).
func perfFor(name string) (perfProfile, error) {
	if name == "" {
		name = "balance"
	}
	p, ok := perfProfiles[strings.ToLower(name)]
	if !ok {
		return perfProfile{}, fmt.Errorf("performance must be one of %s; got %q", perfNames, name)
	}
	return p, nil
}

// applyARQProfile sets the process-wide ARQ tuning for the spoof transports.
// Call it once at startup, before any tunnel conn exists.
func applyARQProfile(name string) {
	p, err := perfFor(name)
	if err != nil {
		return // LoadConfig already rejected unknown names
	}
	arqRecvWnd, arqSendCap = p.ARQWindow, p.ARQWindow
	arqInitCwnd, cwndFloor, fastResend = p.ARQInitCwnd, p.ARQFloor, p.ARQFastRes
	minRTO, arqInterval, arqDelayAck = p.ARQMinRTO, p.ARQInterval, p.ARQDelayAck
	if name != "" {
		logf("info", "performance profile: %s", strings.ToLower(name))
	}
}
