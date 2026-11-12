package main

import (
	"bytes"
	"crypto/rand"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"
)

// simPath is one direction of a datagram path with a one-way delay, random
// loss and an optional rate limit with a small queue (a policer / bottleneck).
type simPath struct {
	delay   time.Duration
	loss    float64
	rateBps float64 // 0 = unlimited
	queue   int     // bytes the bottleneck may hold beyond the rate

	mu      sync.Mutex
	rnd     *mrand.Rand
	backlog float64 // bytes queued at the bottleneck
	last    time.Time
	q       []simPkt
	cond    *sync.Cond
	closed  bool
	dropped int
	passed  int
}

type simPkt struct {
	at   time.Time
	data []byte
}

func newSimPath(delay time.Duration, loss, rateMbps float64, seed uint64) *simPath {
	p := &simPath{delay: delay, loss: loss, rateBps: rateMbps * 1e6 / 8, queue: 64 * 1024,
		rnd: mrand.New(mrand.NewPCG(seed, seed+7)), last: time.Now()}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// send enqueues one datagram (or drops it); never blocks.
func (p *simPath) send(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return io.ErrClosedPipe
	}
	now := time.Now()
	extra := time.Duration(0)
	if p.rateBps > 0 {
		p.backlog -= now.Sub(p.last).Seconds() * p.rateBps
		if p.backlog < 0 {
			p.backlog = 0
		}
		p.last = now
		if p.backlog+float64(len(b)) > float64(p.queue) {
			p.dropped++
			return nil // the bottleneck's queue is full
		}
		p.backlog += float64(len(b))
		extra = time.Duration(p.backlog / p.rateBps * float64(time.Second))
	}
	if p.rnd.Float64() < p.loss {
		p.dropped++
		return nil
	}
	p.passed++
	p.q = append(p.q, simPkt{now.Add(p.delay + extra), append([]byte(nil), b...)})
	p.cond.Signal()
	return nil
}

// deliver feeds arriving datagrams to the receiving conn until closed.
func (p *simPath) deliver(to *arqConn) {
	for {
		p.mu.Lock()
		for len(p.q) == 0 && !p.closed {
			p.cond.Wait()
		}
		if p.closed {
			p.mu.Unlock()
			return
		}
		pk := p.q[0]
		p.q = p.q[1:]
		p.mu.Unlock()
		// sleep only for real waits: a sleep per packet for microseconds would make
		// the simulator, not the conn, the bottleneck (timers are about 1 ms coarse)
		if d := time.Until(pk.at); d > 2*time.Millisecond {
			time.Sleep(d)
		}
		to.input(pk.data)
	}
}

func (p *simPath) close() {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
}

// arqOverPath wires two arqConns over a simulated path (same shape both ways).
func arqOverPath(delay time.Duration, loss, rateMbps float64) (a, b *arqConn, stop func(), fwd *simPath) {
	ab := newSimPath(delay, loss, rateMbps, 1)
	ba := newSimPath(delay, loss, rateMbps, 2)
	la := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1)}
	lb := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2)}
	a = newARQ(ab.send, la, lb)
	b = newARQ(ba.send, lb, la)
	go ab.deliver(b)
	go ba.deliver(a)
	return a, b, func() { a.Close(); b.Close(); ab.close(); ba.close() }, ab
}

// arqRate measures how fast one ARQ conn carries data over the path, in
// Mbit/s, after a warm-up, checking the bytes arrive intact.
func arqRate(t *testing.T, delay time.Duration, loss, rateMbps float64, warm, dur time.Duration) (mbps float64, retrans float64) {
	a, b, stop, fwd := arqOverPath(delay, loss, rateMbps)
	defer stop()
	chunk := make([]byte, 256<<10)
	rand.Read(chunk)
	go func() {
		for {
			if _, err := a.Write(chunk); err != nil {
				return
			}
		}
	}()
	var got int64
	var mu sync.Mutex
	bad := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 64<<10)
		off := 0
		for {
			n, err := b.Read(buf)
			if n > 0 {
				// the stream is the 256 KiB chunk repeated: verify every byte
				for i := 0; i < n; {
					m := len(chunk) - off
					if m > n-i {
						m = n - i
					}
					if !bytes.Equal(buf[i:i+m], chunk[off:off+m]) {
						select {
						case bad <- struct{}{}:
						default:
						}
						return
					}
					i += m
					off = (off + m) % len(chunk)
				}
				mu.Lock()
				got += int64(n)
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	time.Sleep(warm)
	mu.Lock()
	start := got
	mu.Unlock()
	fwd.mu.Lock()
	p0 := fwd.passed + fwd.dropped
	fwd.mu.Unlock()
	time.Sleep(dur)
	mu.Lock()
	n := got - start
	mu.Unlock()
	fwd.mu.Lock()
	sent := fwd.passed + fwd.dropped - p0
	fwd.mu.Unlock()
	select {
	case <-bad:
		t.Fatal("stream corrupted")
	default:
	}
	need := float64(n) / arqMTU
	if need > 0 {
		retrans = float64(sent)/need - 1 // packets sent beyond what the data needed
	}
	return float64(n) * 8 / dur.Seconds() / 1e6, retrans
}

// What one spoof conn carries over paths like the ones pol runs on: an 80 ms
// round trip, clean, with random loss, and through a rate limit.
func TestARQPathRates(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	const oneWay = 40 * time.Millisecond
	cases := []struct {
		name     string
		loss     float64
		rateMbps float64
		min      float64 // Mbit/s the conn must reach
	}{
		{"clean path", 0, 0, 20},
		{"1% random loss", 0.01, 0, 10},
		{"5% random loss", 0.05, 0, 5},
		{"50 Mbit/s rate limit", 0, 50, 8},
		{"50 Mbit/s limit + 1% loss", 0.01, 50, 5},
	}
	for _, c := range cases {
		got, re := arqRate(t, oneWay, c.loss, c.rateMbps, 2*time.Second, 3*time.Second)
		t.Logf("%-28s %7.1f Mbit/s   (%.0f%% extra packets)", c.name, got, re*100)
		if got < c.min {
			t.Errorf("%s: %.1f Mbit/s, want at least %.0f", c.name, got, c.min)
		}
	}
}
