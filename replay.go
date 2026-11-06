package main

import "sync"

// replayWindow is an IPsec/WireGuard-style sliding-window anti-replay filter over
// the per-packet AEAD counter. It accepts each counter at most once and rejects
// anything older than the window. Used by direct (datagram) mode; the reliable
// stream transports instead enforce a strictly increasing counter in aeadConn.
const replayBits = 1024

type replayWindow struct {
	mu   sync.Mutex
	last uint64
	bits [replayBits / 64]uint64
}

func (w *replayWindow) getBit(d uint64) bool { return w.bits[d/64]>>(d%64)&1 == 1 }
func (w *replayWindow) setBit(d uint64)      { w.bits[d/64] |= 1 << (d % 64) }

// shiftUp moves every recorded bit to a higher offset by n (the window slides
// forward as `last` advances); bits that fall past the window are dropped.
func (w *replayWindow) shiftUp(n uint64) {
	if n >= replayBits {
		w.bits = [replayBits / 64]uint64{}
		return
	}
	word := int(n / 64)
	bit := n % 64
	var out [replayBits / 64]uint64
	for i := len(out) - 1; i >= 0; i-- {
		var v uint64
		if i-word >= 0 {
			v = w.bits[i-word] << bit
			if bit != 0 && i-word-1 >= 0 {
				v |= w.bits[i-word-1] >> (64 - bit)
			}
		}
		out[i] = v
	}
	w.bits = out
}

// check returns true if seq is fresh (never seen, within the window) and records
// it. Counters start at 1, so 0 is always rejected.
func (w *replayWindow) check(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if seq == 0 {
		return false
	}
	switch {
	case seq > w.last:
		w.shiftUp(seq - w.last)
		w.last = seq
		w.setBit(0)
		return true
	default:
		d := w.last - seq
		if d >= replayBits {
			return false // too old
		}
		if w.getBit(d) {
			return false // replay
		}
		w.setBit(d)
		return true
	}
}
