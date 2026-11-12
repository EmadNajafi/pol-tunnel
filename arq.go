package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// arqConn is a reliable, ordered, full-duplex stream (implements net.Conn) built
// on top of an unreliable datagram link. It is a compact KCP-style ARQ:
// sliding window, cumulative + selective ACK, RTO with backoff, fast retransmit.
//
// It writes to the wire through the `send` callback and is fed inbound datagrams
// through input(). A background ticker drives (re)transmission.
//
// Segment header (big-endian), 14 bytes:
//
//	cmd[1] flags[1] wnd[2] seq[4] una[4] plen[2] | payload[plen]
//
// cmd: 1=PUSH 2=ACK 3=PING   flags bit0 = FIN (on a PUSH, occupies one seq).
// `una` is the sender's cumulative ack (next seq it still needs); `wnd` is the
// sender's free receive window in segments.

const (
	arqPush byte = 1
	arqAck  byte = 2
	arqPing byte = 3
	arqRST  byte = 4 // abort: the sender closed; best-effort (sent a few times)

	flagFIN = 1 << 0

	arqHeader = 14
	arqMTU    = 1200 // payload bytes per segment

	maxRTO        = 8 * time.Second
	arqInitialRTO = 600 * time.Millisecond // before the first round-trip sample
	idleKeepTk    = 50                     // ticks (×interval) of idleness before a keepalive PING
)

// arqTune is the ARQ tuning. A conn takes the current one when it is created
// and keeps it for life, so a profile change never touches a running conn.
// Each side tunes itself: the window is advertised on the wire, so the two
// ends need not match.
type arqTune struct {
	recvWnd    int     // advertised receive window (segments, at most 65535)
	sendCap    int     // max unacked+queued segments before Write blocks
	initCwnd   int     // congestion window a new conn starts with (segments)
	cwndFloor  int     // keep throughput on genuinely lossy links (KCP-style, gentle)
	fastResend int     // duplicate acks before a fast retransmit
	lossTol    float64 // share of packets resent in a round that is taken as the path, not congestion
	minRTO     time.Duration
	interval   time.Duration // flush tick
	// delayAck batches acks on the tick instead of sending one per packet
	// the moment it arrives: fewer packets and less CPU, slightly slower
	// loss recovery (the bulk-transfer profile).
	delayAck bool
}

// arqTuning is what new conns use: the "balance" values until a performance
// profile replaces them at startup (see performance.go).
var arqTuning atomic.Pointer[arqTune]

func init() {
	arqTuning.Store(&arqTune{recvWnd: 1024, sendCap: 1024, initCwnd: 32, cwndFloor: 8, fastResend: 3, lossTol: 0.02,
		minRTO: 50 * time.Millisecond, interval: 10 * time.Millisecond})
}

type seg struct {
	seq     uint32
	flags   byte
	payload []byte
	// tx bookkeeping (sndBuf only)
	acked    bool
	sentAt   time.Time
	rto      time.Duration
	xmit     int
	fastHits int
}

type arqConn struct {
	t      *arqTune // tuning, fixed when the conn is created
	send   func([]byte) error
	local  net.Addr
	remote net.Addr

	mu sync.Mutex
	rc *sync.Cond // read waiters / write-window waiters
	wk chan struct{}

	// send side
	sndUna   uint32
	sndNext  uint32
	sndBuf   []*seg // in flight, seq ascending from sndUna
	sndQueue []*seg // created, not yet admitted to the window
	rmtWnd   uint32
	cwnd     int // congestion window (segments)
	ssthresh int // slow start (doubling) below this, steady growth above
	// congestion is judged over one round (about a round trip), see endRound
	roundAt   time.Time
	roundSent int // first transmissions this round
	roundLost int // retransmissions this round (timeouts and fast resends)
	// pacing, see flush
	tokens    float64
	paceAt    time.Time
	obuf      []byte    // scratch for one outgoing datagram
	toAllow   int       // while the path is silent: how many of the oldest segments may time out per flush
	lastAckAt time.Time // when an ack last arrived
	srtt      time.Duration
	rttvar    time.Duration
	finSeq    uint32
	finSent   bool

	// recv side
	rcvNext     uint32
	lastAckSent uint32
	lastWndSent uint16
	rcvBuf      map[uint32]*seg
	rStream     []byte
	rEOF        bool
	acks        []uint32

	closed   bool
	closeErr error

	rdDead, wrDead time.Time
	rdTmr, wrTmr   *time.Timer
}

func newARQ(send func([]byte) error, local, remote net.Addr) *arqConn {
	t := arqTuning.Load()
	c := &arqConn{
		t:    t,
		send: send, local: local, remote: remote,
		wk:          make(chan struct{}, 1),
		rmtWnd:      uint32(t.recvWnd),
		lastWndSent: uint16(t.recvWnd),
		cwnd:        t.initCwnd,
		ssthresh:    1 << 20,
		tokens:      float64(t.initCwnd),
		rcvBuf:      map[uint32]*seg{},
	}
	c.rc = sync.NewCond(&c.mu)
	go c.updater()
	return c
}

func seqLess(a, b uint32) bool { return int32(a-b) < 0 }

// ---- RTT / RTO ----

func (c *arqConn) rto() time.Duration {
	if c.srtt == 0 {
		// Nothing measured yet. This used to be 100 ms, which a path with an
		// 80 ms round trip beats only just: the first flight often timed out
		// although nothing was lost, and that one event ended slow start.
		return arqInitialRTO
	}
	// The margin over the smoothed round trip must never shrink to nothing:
	// on a steady path rttvar decays to zero, and with rto = srtt every packet
	// that arrived a moment late was resent although nothing was lost.
	margin := 4 * c.rttvar
	if margin < c.srtt/2 {
		margin = c.srtt / 2
	}
	rto := c.srtt + margin + c.t.interval // + one flush tick of ack delay
	if rto < c.t.minRTO {
		rto = c.t.minRTO
	}
	if rto > maxRTO {
		rto = maxRTO
	}
	return rto
}

func (c *arqConn) updateRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if c.srtt == 0 {
		c.srtt, c.rttvar = sample, sample/2
		return
	}
	d := c.srtt - sample
	if d < 0 {
		d = -d
	}
	c.rttvar = (3*c.rttvar + d) / 4
	c.srtt = (7*c.srtt + sample) / 8
}

func (c *arqConn) signal() {
	select {
	case c.wk <- struct{}{}:
	default:
	}
}

// ---- receive path ----

func (c *arqConn) input(data []byte) {
	c.mu.Lock()
	woke := false
	for len(data) >= arqHeader {
		cmd := data[0]
		flags := data[1]
		wnd := binary.BigEndian.Uint16(data[2:])
		seqn := binary.BigEndian.Uint32(data[4:])
		una := binary.BigEndian.Uint32(data[8:])
		plen := int(binary.BigEndian.Uint16(data[12:]))
		if arqHeader+plen > len(data) {
			break
		}
		payload := data[arqHeader : arqHeader+plen]
		data = data[arqHeader+plen:]

		c.rmtWnd = uint32(wnd)
		c.processUna(una)
		switch cmd {
		case arqAck:
			c.lastAckAt = time.Now()
			// seqn is a selective ack for a *received* segment. A frame whose
			// seqn equals its own una is a cumulative-only ack (seqn = rcvNext,
			// the next expected / missing seq) — never mark that as received.
			if seqn != una {
				c.processAck(seqn)
			}
			woke = true
		case arqPush:
			c.onPush(seqn, flags, payload)
			if !c.t.delayAck { // batched acks go out on the next tick instead
				woke = true
			}
		case arqPing:
		case arqRST:
			c.failLocked(errPeerReset)
		}
	}
	c.mu.Unlock()
	if woke {
		c.signal()
	}
}

// processUna drops in-flight segments the peer has cumulatively acked.
func (c *arqConn) processUna(una uint32) {
	n := 0
	for len(c.sndBuf) > 0 && seqLess(c.sndBuf[0].seq, una) {
		s := c.sndBuf[0]
		// (no round-trip sample here: a cumulative ack can cover a segment long
		// after it arrived, when its own ack was lost, and such samples blew the
		// smoothed round trip, and with it every timeout, up to seconds on a lossy
		// path; samples come only from a segment's own ack, in processAck)
		c.sndBuf = c.sndBuf[1:]
		c.sndUna = s.seq + 1
		n++
	}
	c.grow(n)
	c.rc.Broadcast()
}

func (c *arqConn) processAck(seq uint32) {
	for _, s := range c.sndBuf {
		if s.seq == seq {
			if !s.acked && s.xmit == 1 {
				c.updateRTT(time.Since(s.sentAt))
			}
			s.acked = true
		} else if seqLess(s.seq, seq) && !s.acked {
			s.fastHits++
		}
	}
	n := 0
	for len(c.sndBuf) > 0 && c.sndBuf[0].acked {
		c.sndUna = c.sndBuf[0].seq + 1
		c.sndBuf = c.sndBuf[1:]
		n++
	}
	c.grow(n)
	c.rc.Broadcast()
}

// grow is slow start: below ssthresh every acknowledged segment adds one to
// the window, which doubles it each round trip. Above ssthresh the window
// moves once per round, in endRound.
func (c *arqConn) grow(acked int) {
	if c.cwnd < c.ssthresh {
		c.cwnd += acked
	}
	c.clampCwnd()
}

func (c *arqConn) clampCwnd() {
	if c.cwnd > c.t.sendCap {
		c.cwnd = c.t.sendCap
	}
	if c.cwnd < c.t.cwndFloor {
		c.cwnd = c.t.cwndFloor
	}
}

// endRound judges congestion once per round trip, from the share of packets
// that had to be sent again in that round, not from single losses. The old
// rule halved the window on any loss and then grew it by one segment per round
// trip: one early timeout, or the 1% random loss these paths always have,
// pinned a conn near its floor (about 1-2 Mbit/s at 80 ms). Now a loss share
// under the profile's tolerance is taken as the path's noise and ignored;
// above it the window is cut by that share (at most half), which settles just
// under a rate limit; and without congestion it grows by an eighth per round.
func (c *arqConn) endRound(now time.Time) {
	round := c.srtt
	if round < 50*time.Millisecond {
		round = 50 * time.Millisecond
	}
	if c.roundAt.IsZero() {
		c.roundAt = now
		return
	}
	if now.Sub(c.roundAt) < round {
		return
	}
	sent, lost := c.roundSent, c.roundLost
	c.roundAt, c.roundSent, c.roundLost = now, 0, 0
	if sent+lost == 0 {
		return
	}
	share := float64(lost) / float64(sent+lost)
	// Cut by how far the resent share is above the tolerance, then probe
	// upward by a sixteenth. On a path with random loss below the tolerance
	// the window keeps growing; at a rate limit it settles where the two
	// balance, a few percent of resends above the tolerance.
	if excess := share - c.t.lossTol; excess > 0 {
		if excess > 0.5 {
			excess = 0.5
		}
		c.cwnd = int(float64(c.cwnd) * (1 - excess))
		c.clampCwnd()
		if c.ssthresh > c.cwnd {
			c.ssthresh = c.cwnd // congestion found: slow start is over
		}
	}
	if c.cwnd >= c.ssthresh {
		step := c.cwnd / 16
		if step < 1 {
			step = 1
		}
		c.cwnd += step
		c.clampCwnd()
	}
}

func (c *arqConn) onPush(seq uint32, flags byte, payload []byte) {
	c.acks = append(c.acks, seq) // ack even duplicates/out-of-window frames
	if seqLess(seq, c.rcvNext) || seq-c.rcvNext >= uint32(c.t.recvWnd) {
		return
	}
	if _, dup := c.rcvBuf[seq]; dup {
		return
	}
	// payload is a slice of the datagram input() was handed, which is ours to keep
	c.rcvBuf[seq] = &seg{seq: seq, flags: flags, payload: payload}
	for {
		s, ok := c.rcvBuf[c.rcvNext]
		if !ok {
			break
		}
		delete(c.rcvBuf, c.rcvNext)
		c.rStream = append(c.rStream, s.payload...)
		if s.flags&flagFIN != 0 {
			c.rEOF = true
		}
		c.rcvNext++
	}
	c.rc.Broadcast()
}

func (c *arqConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if len(c.rStream) > 0 {
			n := copy(p, c.rStream)
			c.rStream = c.rStream[n:]
			if len(c.rStream) == 0 {
				c.rStream = nil
			}
			return n, nil
		}
		if c.rEOF {
			return 0, io.EOF
		}
		if c.closed {
			return 0, c.closeErr
		}
		if !c.rdDead.IsZero() && !time.Now().Before(c.rdDead) {
			return 0, timeoutErr{}
		}
		c.rc.Wait()
	}
}

// ---- send path ----

func (c *arqConn) pending() int { return len(c.sndBuf) + len(c.sndQueue) }

// unacked counts in-flight segments not yet acknowledged. Acked segments trapped
// behind an earlier hole do not count against the congestion window.
func (c *arqConn) unacked() int {
	n := 0
	for _, s := range c.sndBuf {
		if !s.acked {
			n++
		}
	}
	return n
}

func (c *arqConn) sendWindow() int {
	w := c.cwnd
	if int(c.rmtWnd) < w {
		w = int(c.rmtWnd)
	}
	if w > c.t.sendCap {
		w = c.t.sendCap
	}
	if w < 1 {
		w = 1 // let a zero window probe so it can recover
	}
	return w
}

func (c *arqConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.finSent {
		return 0, errARQClosed
	}
	total := len(p)
	for len(p) > 0 {
		for c.pending() >= c.t.sendCap {
			if c.closed {
				return total - len(p), c.closeErr
			}
			if !c.wrDead.IsZero() && !time.Now().Before(c.wrDead) {
				return total - len(p), timeoutErr{}
			}
			c.rc.Wait()
			if c.closed || c.finSent {
				return total - len(p), errARQClosed
			}
		}
		n := len(p)
		if n > arqMTU {
			n = arqMTU
		}
		c.sndQueue = append(c.sndQueue, &seg{seq: c.sndNext, payload: append([]byte(nil), p[:n]...)})
		c.sndNext++
		p = p[n:]
	}
	c.signal()
	return total, nil
}

func (c *arqConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finSent || c.closed {
		return nil
	}
	c.finSent = true
	c.finSeq = c.sndNext
	c.sndQueue = append(c.sndQueue, &seg{seq: c.sndNext, flags: flagFIN})
	c.sndNext++
	c.signal()
	return nil
}

// ---- periodic flush ----

func (c *arqConn) updater() {
	t := time.NewTicker(c.t.interval)
	defer t.Stop()
	idle := 0
	for {
		select {
		case <-t.C:
			idle++
		case <-c.wk:
			idle = 0
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.flush(idle)
		c.mu.Unlock()
	}
}

// recvWindow is the free receive window advertised to the peer, in segments.
// Delivered-but-unread bytes (rStream) count against it too: without that a
// fast sender and a slow reader (e.g. a download to a slow visitor) would grow
// rStream without bound, since the window would never shrink.
func (c *arqConn) recvWindow() uint16 {
	free := c.t.recvWnd - len(c.rcvBuf) - (len(c.rStream)+arqMTU-1)/arqMTU
	if free < 0 {
		free = 0
	}
	return uint16(free)
}

func (c *arqConn) flush(idle int) {
	now := time.Now()
	wnd := c.recvWindow()

	// ---- acks: several fit in one datagram, so batch them ----
	c.obuf = c.obuf[:0]
	addAck := func(seq uint32) {
		if len(c.obuf)+arqHeader > arqMTU {
			c.sendOut()
		}
		c.obuf = c.appendSeg(c.obuf, arqAck, 0, seq, wnd, nil)
	}
	// The window reopened after the application drained a backlog: tell the
	// sender now instead of waiting for its next zero-window probe.
	if int(c.lastWndSent) < c.t.recvWnd/4 && int(wnd) >= c.t.recvWnd/2 && len(c.acks) == 0 && c.rcvNext == c.lastAckSent {
		addAck(c.rcvNext)
	}
	c.lastWndSent = wnd
	for _, seq := range c.acks {
		addAck(seq)
	}
	c.acks = c.acks[:0]
	// Redundant cumulative ack whenever we delivered new in-order data: carries
	// `una` (= rcvNext) so the sender keeps advancing even if selective acks are lost.
	if c.rcvNext != c.lastAckSent {
		addAck(c.rcvNext)
		c.lastAckSent = c.rcvNext
	}
	c.sendOut()

	// ---- pacing: a token per packet, refilled at twice the window per round
	// trip, so a window is spread over the round trip instead of leaving as
	// one burst (which overflowed socket buffers and policers on the path and
	// came back as loss) ----
	rtt := c.srtt
	if rtt == 0 {
		rtt = 200 * time.Millisecond // nothing measured yet
	}
	rate := 2 * float64(c.cwnd) / rtt.Seconds()
	if !c.paceAt.IsZero() {
		c.tokens += rate * now.Sub(c.paceAt).Seconds()
	}
	c.paceAt = now
	burst := rate * 2 * c.t.interval.Seconds()
	if burst < 16 {
		burst = 16
	}
	if c.tokens > burst {
		c.tokens = burst
	}

	win := c.sendWindow()
	for ua := c.unacked(); len(c.sndQueue) > 0 && ua < win; ua++ {
		c.sndBuf = append(c.sndBuf, c.sndQueue[0])
		c.sndQueue = c.sndQueue[1:]
	}

	// How many of the oldest unacked segments may time out in this flush.
	// While acks are arriving, a segment whose timer ran out really is lost
	// (its neighbours were acknowledged), so all of them may go. When nothing
	// at all has arrived for a while the whole window looks late at once —
	// that is a delay spike or a dead path, not a window of losses — so only
	// the oldest is probed, doubling each flush while it stays silent.
	quiet := c.srtt > 0 && now.Sub(c.lastAckAt) > c.srtt/2+2*c.t.interval
	allow, ahead, resent := len(c.sndBuf), 0, 0
	if quiet {
		allow = c.toAllow
		if allow < 1 {
			allow = 1
		}
	} else {
		c.toAllow = 1
	}
	for _, s := range c.sndBuf {
		if s.acked {
			continue
		}
		// Only the oldest unacked segments may time out in one flush. After a
		// delay spike the whole window is "late" at once; resending all of it
		// was hundreds of needless packets and a collapsed window, when a
		// moment later the acks arrive. The allowance doubles while timeouts
		// keep happening (a really lost burst) and resets once normal acks flow.
		ahead++
		timeout := s.xmit > 0 && ahead <= allow && now.Sub(s.sentAt) >= s.rto
		// A fast resend at most once per round trip for a segment: acks of
		// packets sent before the resend keep arriving for a whole round trip
		// and each used to count as a new hint, so one lost packet was resent
		// dozens of times (and all of them were booked as loss).
		fast := s.xmit > 0 && s.fastHits >= c.t.fastResend && (s.xmit == 1 || now.Sub(s.sentAt) >= c.srtt+c.srtt/4)
		if s.xmit > 0 && !timeout && !fast {
			continue // in flight, nothing to do yet
		}
		if c.tokens < 1 {
			break // paced: the rest go out on the next flush
		}
		c.tokens--
		switch {
		case s.xmit == 0:
			s.rto = c.rto()
			c.roundSent++
		case timeout:
			c.roundLost++
			resent++
			s.rto = s.rto * 3 / 2
			if s.rto > 2*time.Second { // cap so a persistently-lost segment retries promptly
				s.rto = 2 * time.Second
			}
		default: // fast retransmit
			c.roundLost++
			s.fastHits = 0
		}
		s.xmit++
		s.sentAt = now
		c.obuf = c.appendSeg(c.obuf[:0], arqPush, s.flags, s.seq, wnd, s.payload)
		c.sendOut()
	}
	if resent > 0 {
		// more may time out next round if these were not enough (a lost burst)
		c.toAllow = allow * 2
		if c.toAllow > c.cwnd {
			c.toAllow = c.cwnd
		}
	}
	c.endRound(now)

	if idle >= idleKeepTk && len(c.sndBuf) == 0 && len(c.sndQueue) == 0 {
		c.emit(arqPing, 0, c.sndNext, wnd, nil)
	}
}

// appendSeg appends one segment (header + payload) to b.
func (c *arqConn) appendSeg(b []byte, cmd, flags byte, seq uint32, wnd uint16, payload []byte) []byte {
	var h [arqHeader]byte
	h[0], h[1] = cmd, flags
	binary.BigEndian.PutUint16(h[2:], wnd)
	binary.BigEndian.PutUint32(h[4:], seq)
	binary.BigEndian.PutUint32(h[8:], c.rcvNext)
	binary.BigEndian.PutUint16(h[12:], uint16(len(payload)))
	b = append(b, h[:]...)
	return append(b, payload...)
}

// sendOut sends what is in obuf as one datagram (the send callback copies it).
func (c *arqConn) sendOut() {
	if len(c.obuf) == 0 {
		return
	}
	if err := c.send(c.obuf); err != nil {
		c.failLocked(err)
	}
	c.obuf = c.obuf[:0]
}

func (c *arqConn) emit(cmd, flags byte, seq uint32, wnd uint16, payload []byte) {
	c.obuf = c.appendSeg(c.obuf[:0], cmd, flags, seq, wnd, payload)
	c.sendOut()
}

// ---- close & net.Conn plumbing ----

// Close shuts the stream down gracefully: it waits (up to a short linger) for
// our already-queued data to be acknowledged, so the RST we send to release the
// peer's state can never overtake unsent data and truncate the peer's read.
func (c *arqConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for (len(c.sndBuf) > 0 || len(c.sndQueue) > 0) && !c.closed {
		if time.Now().After(deadline) {
			break
		}
		c.arm(&c.wrTmr, deadline)
		c.rc.Wait()
	}
	for i := 0; i < 3; i++ { // best-effort: release peer state promptly
		c.emitRST()
	}
	c.failLocked(errARQClosed)
	return nil
}

func (c *arqConn) emitRST() {
	b := make([]byte, arqHeader)
	b[0] = arqRST
	binary.BigEndian.PutUint16(b[2:], uint16(c.t.recvWnd))
	binary.BigEndian.PutUint32(b[8:], c.rcvNext)
	c.send(b) // ignore errors: the conn is going away
}

func (c *arqConn) failLocked(err error) {
	if c.closed {
		return
	}
	c.closed = true
	c.closeErr = err
	c.rc.Broadcast()
	c.signal()
}

func (c *arqConn) LocalAddr() net.Addr  { return c.local }
func (c *arqConn) RemoteAddr() net.Addr { return c.remote }

func (c *arqConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *arqConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdDead = t
	c.arm(&c.rdTmr, t)
	c.mu.Unlock()
	return nil
}

func (c *arqConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wrDead = t
	c.arm(&c.wrTmr, t)
	c.mu.Unlock()
	return nil
}

func (c *arqConn) arm(tmr **time.Timer, t time.Time) {
	if *tmr != nil {
		(*tmr).Stop()
		*tmr = nil
	}
	if t.IsZero() {
		return
	}
	d := time.Until(t)
	if d < 0 {
		d = 0
	}
	*tmr = time.AfterFunc(d, func() { c.mu.Lock(); c.rc.Broadcast(); c.mu.Unlock() })
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var errARQClosed = errors.New("arq: connection closed")
var errPeerReset = errors.New("arq: connection reset by peer")

var _ net.Conn = (*arqConn)(nil)
