package main

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Auto MTU for direct mode.
//
// Each side measures its own sending direction: it sends authenticated DATA
// packets padded to a chosen size and the peer acknowledges each one it gets.
// A binary search over the UDP payload size finds the largest one that
// arrives, and the interface MTU becomes that size minus directOverhead. While
// measuring, the sockets set Don't Fragment and ignore the kernel's cached
// path MTU (IP_PMTUDISC_PROBE), so an oversize probe is dropped on the route
// instead of being fragmented and passing anyway. The measurement repeats
// every directMTUInterval. If the peer never answers (an older pol), the
// configured mtu is kept.
//
// Control messages travel inside sealed DATA packets:
//
//	probe:     0x00 | 0x01 | id[4] | zero padding
//	probe ack: 0x00 | 0x02 | id[4]

const (
	ctlMarker   byte = 0x00
	ctlProbe    byte = 0x01
	ctlProbeAck byte = 0x02
	ctlHdr           = 6 // marker + type + id

	// UDP payload sizes searched. 548 is what a 576-byte IPv4 path carries;
	// 1472 is the most a 1500-byte Ethernet path carries.
	mtuProbeMin = 548
	mtuProbeMax = 1472
)

// tunables (tests shorten them)
var (
	directMTUInterval  = 30 * time.Minute
	directProbeTimeout = time.Second
	directProbeTries   = 2
)

func (e *directEngine) handleControl(plain []byte, path int) {
	if len(plain) < ctlHdr {
		return
	}
	switch plain[1] {
	case ctlProbe:
		ack := make([]byte, ctlHdr)
		ack[0], ack[1] = ctlMarker, ctlProbeAck
		copy(ack[2:], plain[2:ctlHdr])
		e.sendData(ack, path)
	case ctlProbeAck:
		select {
		case e.probeAcks <- binary.BigEndian.Uint32(plain[2:ctlHdr]):
		default:
		}
	}
}

// probe reports whether a DATA packet with a UDP payload of size bytes reaches
// the peer (and its ack comes back).
func (e *directEngine) probe(size int) bool {
	plainLen := size - directOverhead
	if plainLen < ctlHdr {
		plainLen = ctlHdr
	}
	for try := 0; try < directProbeTries; try++ {
		var idb [4]byte
		rand.Read(idb[:])
		id := binary.BigEndian.Uint32(idb[:])
		msg := make([]byte, plainLen)
		msg[0], msg[1] = ctlMarker, ctlProbe
		copy(msg[2:], idb[:])
		e.sendData(msg, 0)
		deadline := time.NewTimer(directProbeTimeout)
	wait:
		for {
			select {
			case got := <-e.probeAcks:
				if got == id {
					deadline.Stop()
					return true
				}
			case <-deadline.C:
				break wait
			}
		}
	}
	return false
}

// measureMTU returns the largest UDP payload size that reaches the peer, or 0
// if not even the smallest one does.
func (e *directEngine) measureMTU() int {
	e.setPMTUProbe(true)
	defer e.setPMTUProbe(false)
	lo, hi := mtuProbeMin, mtuProbeMax
	if !e.probe(lo) {
		return 0
	}
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if e.probe(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// setPMTUProbe turns Don't-Fragment probing on or off on every path.
func (e *directEngine) setPMTUProbe(on bool) {
	for _, p := range e.paths {
		if err := setPMTUProbe(p.sock, on); err != nil {
			logf("debug", "direct: path %d: pmtu probe mode: %v", p.idx, err)
		}
		if d, ok := p.sender.(interface{ setDF(bool) }); ok {
			d.setDF(on)
		}
	}
}

func (e *directEngine) isUp() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.up
}

func (e *directEngine) currentMTU() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mtu
}

// autoMTULoop measures once the tunnel is up, then every directMTUInterval.
func (e *directEngine) autoMTULoop() {
	for {
		for !e.isUp() {
			time.Sleep(time.Second)
		}
		best := e.measureMTU()
		if best == 0 {
			logf("warn", "direct: auto MTU: the peer did not answer probes (older pol on the other side?); keeping mtu %d", e.currentMTU())
		} else if mtu := best - directOverhead; mtu != e.currentMTU() {
			if err := e.dev.setMTU(mtu); err != nil {
				logf("warn", "direct: auto MTU: set mtu %d: %v", mtu, err)
			} else {
				e.mu.Lock()
				old := e.mtu
				e.mtu = mtu
				e.mu.Unlock()
				logf("info", "direct: auto MTU: route carries %d-byte datagrams, interface mtu %d -> %d", best, old, mtu)
			}
		}
		time.Sleep(directMTUInterval)
	}
}
