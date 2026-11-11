package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
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

	maxRTO     = 8 * time.Second
	idleKeepTk = 50 // ticks (×interval) of idleness before a keepalive PING
)

// ARQ tuning. These are the "balance" values; a performance profile replaces
// them once at startup, before any conn exists (see performance.go). Each side
// tunes itself: the window is advertised on the wire, so the two ends need not
// match.
var (
	arqRecvWnd  = 1024 // advertised receive window (segments, at most 65535)
	arqSendCap  = 1024 // max unacked+queued segments before Write blocks
	arqInitCwnd = 32   // congestion window a new conn starts with (segments)
	cwndFloor   = 8    // keep throughput on genuinely lossy links (KCP-style, gentle)
	fastResend  = 3    // duplicate acks before a fast retransmit
	minRTO      = 50 * time.Millisecond
	arqInterval = 10 * time.Millisecond
	// arqDelayAck batches acks on the tick instead of sending one per packet
	// the moment it arrives: fewer packets and less CPU, slightly slower loss
	// recovery (the bulk-transfer profile).
	arqDelayAck = false
)

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
	cwnd     int // congestion window (segments), AIMD
	ssthresh int
	ackAcc   int
	lastLoss time.Time
	srtt     time.Duration
	rttvar   time.Duration
	finSeq   uint32
	finSent  bool

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
	c := &arqConn{
		send: send, local: local, remote: remote,
		wk:          make(chan struct{}, 1),
		rmtWnd:      uint32(arqRecvWnd),
		lastWndSent: uint16(arqRecvWnd),
		cwnd:        arqInitCwnd,
		ssthresh:    1 << 20,
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
		return 2 * minRTO
	}
	rto := c.srtt + 4*c.rttvar
	if rto < minRTO {
		rto = minRTO
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
			// seqn is a selective ack for a *received* segment. A frame whose
			// seqn equals its own una is a cumulative-only ack (seqn = rcvNext,
			// the next expected / missing seq) — never mark that as received.
			if seqn != una {
				c.processAck(seqn)
			}
			woke = true
		case arqPush:
			c.onPush(seqn, flags, payload)
			if !arqDelayAck { // batched acks go out on the next tick instead
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
		if s.xmit == 1 {
			c.updateRTT(time.Since(s.sentAt))
		}
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

// grow advances the congestion window: slow start below ssthresh, then
// congestion avoidance (roughly +1 segment per window of acks).
func (c *arqConn) grow(acked int) {
	for i := 0; i < acked; i++ {
		if c.cwnd < c.ssthresh {
			c.cwnd++
		} else {
			c.ackAcc++
			if c.ackAcc >= c.cwnd {
				c.ackAcc = 0
				c.cwnd++
			}
		}
	}
	if c.cwnd > arqSendCap {
		c.cwnd = arqSendCap
	}
}

// backoff reacts to loss: ssthresh = cwnd/2, and cwnd drops (hard on a timeout,
// to ssthresh on fast retransmit).
func (c *arqConn) backoff(timeout bool) {
	// Gentle, KCP-style: halve on timeout, 3/4 on fast retransmit, never below
	// the floor, so a link with real packet loss keeps moving.
	if timeout {
		c.cwnd = c.cwnd / 2
	} else {
		c.cwnd = c.cwnd * 3 / 4
	}
	if c.cwnd < cwndFloor {
		c.cwnd = cwndFloor
	}
	c.ssthresh = c.cwnd
	c.ackAcc = 0
}

func (c *arqConn) onPush(seq uint32, flags byte, payload []byte) {
	c.acks = append(c.acks, seq) // ack even duplicates/out-of-window frames
	if seqLess(seq, c.rcvNext) || seq-c.rcvNext >= uint32(arqRecvWnd) {
		return
	}
	if _, dup := c.rcvBuf[seq]; dup {
		return
	}
	c.rcvBuf[seq] = &seg{seq: seq, flags: flags, payload: append([]byte(nil), payload...)}
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
	if w > arqSendCap {
		w = arqSendCap
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
		for c.pending() >= arqSendCap {
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
	t := time.NewTicker(arqInterval)
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
	free := arqRecvWnd - len(c.rcvBuf) - (len(c.rStream)+arqMTU-1)/arqMTU
	if free < 0 {
		free = 0
	}
	return uint16(free)
}

func (c *arqConn) flush(idle int) {
	now := time.Now()
	wnd := c.recvWindow()

	// The window reopened after the application drained a backlog: tell the
	// sender now instead of waiting for its next zero-window probe.
	if int(c.lastWndSent) < arqRecvWnd/4 && int(wnd) >= arqRecvWnd/2 && len(c.acks) == 0 && c.rcvNext == c.lastAckSent {
		c.emit(arqAck, 0, c.rcvNext, wnd, nil)
	}
	c.lastWndSent = wnd

	for _, seq := range c.acks {
		c.emit(arqAck, 0, seq, wnd, nil)
	}
	c.acks = c.acks[:0]
	// Redundant cumulative ack whenever we delivered new in-order data: carries
	// `una` (= rcvNext) so the sender keeps advancing even if selective acks are lost.
	if c.rcvNext != c.lastAckSent {
		c.emit(arqAck, 0, c.rcvNext, wnd, nil)
		c.lastAckSent = c.rcvNext
	}

	win := c.sendWindow()
	for ua := c.unacked(); len(c.sndQueue) > 0 && ua < win; ua++ {
		c.sndBuf = append(c.sndBuf, c.sndQueue[0])
		c.sndQueue = c.sndQueue[1:]
	}

	timeoutLoss, fastLoss := false, false
	for _, s := range c.sndBuf {
		if s.acked {
			continue
		}
		resend := false
		switch {
		case s.xmit == 0:
			resend = true
			s.rto = c.rto()
		case now.Sub(s.sentAt) >= s.rto:
			resend = true
			timeoutLoss = true
			s.rto *= 2
			if s.rto > 2*time.Second { // cap so a persistently-lost segment retries promptly
				s.rto = 2 * time.Second
			}
		case s.fastHits >= fastResend:
			resend = true
			fastLoss = true
			s.fastHits = 0
		}
		if resend {
			s.xmit++
			s.sentAt = now
			c.emit(arqPush, s.flags, s.seq, wnd, s.payload)
		}
	}
	// React to loss at most once per RTT (one loss event), so random packet loss
	// doesn't pin the window at the floor the way per-segment backoff would.
	if timeoutLoss || fastLoss {
		interval := c.srtt
		if interval < 100*time.Millisecond {
			interval = 100 * time.Millisecond
		}
		if now.Sub(c.lastLoss) >= interval {
			c.backoff(timeoutLoss)
			c.lastLoss = now
		}
	}

	if idle >= idleKeepTk && len(c.sndBuf) == 0 && len(c.sndQueue) == 0 {
		c.emit(arqPing, 0, c.sndNext, wnd, nil)
	}
}

func (c *arqConn) emit(cmd, flags byte, seq uint32, wnd uint16, payload []byte) {
	b := make([]byte, arqHeader+len(payload))
	b[0], b[1] = cmd, flags
	binary.BigEndian.PutUint16(b[2:], wnd)
	binary.BigEndian.PutUint32(b[4:], seq)
	binary.BigEndian.PutUint32(b[8:], c.rcvNext)
	binary.BigEndian.PutUint16(b[12:], uint16(len(payload)))
	copy(b[arqHeader:], payload)
	if err := c.send(b); err != nil {
		c.failLocked(err)
	}
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
	binary.BigEndian.PutUint16(b[2:], uint16(arqRecvWnd))
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
