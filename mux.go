package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// A small stream multiplexer (the role smux/yamux play in Backhaul / BackPack).
//
// Frame: cmd[1] | streamID[4] | length[2] | payload[length]
//
// Flow control is per stream and credit based: every stream starts with
// initialWindow bytes of send credit; the receiver hands out more credit (WND)
// as its application consumes data, so a slow consumer can never make the
// other side buffer unbounded data or stall unrelated streams.

const (
	cmdSYN  byte = 1 // payload = open header
	cmdDATA byte = 2
	cmdFIN  byte = 3 // sender will write no more (half close)
	cmdRST  byte = 4 // abort stream
	cmdWND  byte = 5 // payload = uint32 extra credit
	cmdPING byte = 6
	cmdPONG byte = 7

	frameHeader   = 7
	initialWindow = 256 * 1024
)

var errStreamClosed = errors.New("stream closed")
var errSessionClosed = errors.New("session closed")

type Session struct {
	conn      net.Conn
	frameSize int
	window    int // the receive window a stream starts with
	maxWindow int // how far a stream's receive window may grow on its own

	wmu     sync.Mutex
	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32

	accept    chan *Stream
	closed    chan struct{}
	closeOnce sync.Once
	lastRecv  atomic.Int64

	pingAt atomic.Int64 // unix nanos of the ping awaiting its pong (0 = none)
	rtt    atomic.Int64 // smallest round trip seen, nanos (0 = not measured yet)
}

// NewSession is a session whose stream windows stay at `window`.
func NewSession(c net.Conn, frameSize, window int, heartbeat time.Duration) *Session {
	return NewSessionTuned(c, frameSize, window, window, heartbeat)
}

// NewSessionTuned is a session whose stream receive windows start at `window`
// and grow up to maxWindow while the window, not the reader, is what limits a
// stream (see Stream.Read). One stream is paced by window / round trip, so on
// a long path a fixed small window is slow and a fixed large one costs memory
// for every stream; growing on demand gives the speed only where it is used.
func NewSessionTuned(c net.Conn, frameSize, window, maxWindow int, heartbeat time.Duration) *Session {
	if maxWindow < window {
		maxWindow = window
	}
	s := &Session{
		conn:      c,
		frameSize: frameSize,
		window:    window,
		maxWindow: maxWindow,
		streams:   map[uint32]*Stream{},
		nextID:    1,
		accept:    make(chan *Stream, 1024),
		closed:    make(chan struct{}),
	}
	s.lastRecv.Store(time.Now().UnixNano())
	go s.recvLoop()
	go s.keepalive(heartbeat)
	return s
}

// ping sends a PING and notes when, so the PONG gives a round-trip sample.
func (s *Session) ping() {
	s.pingAt.Store(time.Now().UnixNano())
	s.writeFrame(cmdPING, 0, nil)
}

// framePool recycles frame buffers: writeFrame used to allocate one per frame.
var framePool = sync.Pool{New: func() any { b := make([]byte, frameHeader+0xffff); return &b }}

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.conn.Close()
		s.mu.Lock()
		for _, st := range s.streams {
			st.abort()
		}
		s.streams = map[uint32]*Stream{}
		s.mu.Unlock()
	})
	return nil
}

func (s *Session) IsClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *Session) Done() <-chan struct{} { return s.closed }

func (s *Session) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

func (s *Session) writeFrame(cmd byte, id uint32, p []byte) error {
	bp := framePool.Get().(*[]byte)
	defer framePool.Put(bp)
	b := (*bp)[:frameHeader+len(p)]
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:], id)
	binary.BigEndian.PutUint16(b[5:], uint16(len(p)))
	copy(b[frameHeader:], p)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.IsClosed() {
		return errSessionClosed
	}
	if _, err := s.conn.Write(b); err != nil {
		go s.Close()
		return err
	}
	return nil
}

// Open creates a new stream and sends SYN carrying the open header.
func (s *Session) Open(proto byte, target, src string) (*Stream, error) {
	s.mu.Lock()
	if s.IsClosed() {
		s.mu.Unlock()
		return nil, errSessionClosed
	}
	id := s.nextID
	s.nextID++
	st := newStream(s, id)
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.writeFrame(cmdSYN, id, encodeOpen(proto, target, src)); err != nil {
		return nil, err
	}
	st.grantExtra()
	return st, nil
}

// Accept returns the next stream opened by the peer plus its open header.
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.closed:
		return nil, errSessionClosed
	}
}

func (s *Session) keepalive(every time.Duration) {
	go s.ping() // a first round-trip sample right away, for the window tuning
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-t.C:
			if time.Since(time.Unix(0, s.lastRecv.Load())) > 3*every {
				logf("warn", "mux session %s: peer silent for %v, closing", s.conn.RemoteAddr(), 3*every)
				s.Close()
				return
			}
			// Never ping from this goroutine: with the path blackholed and
			// data in flight, a writer sits in conn.Write holding the write
			// lock, the ping would queue behind it, and the silence check
			// above would never run again — the session then hung until TCP
			// itself gave up, many minutes later.
			go s.ping()
		}
	}
}

func (s *Session) recvLoop() {
	defer s.Close()
	// buffered: a frame used to cost two read syscalls (header, then payload)
	r := bufio.NewReaderSize(s.conn, 64*1024)
	hdr := make([]byte, frameHeader)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}
		s.lastRecv.Store(time.Now().UnixNano())
		cmd := hdr[0]
		id := binary.BigEndian.Uint32(hdr[1:])
		n := int(binary.BigEndian.Uint16(hdr[5:]))
		var p []byte
		if n > 0 {
			p = make([]byte, n)
			if _, err := io.ReadFull(r, p); err != nil {
				return
			}
		}
		switch cmd {
		case cmdPING:
			go s.writeFrame(cmdPONG, 0, nil)
		case cmdPONG:
			// a round-trip sample; keep the smallest (a ping can sit behind data
			// in the write queue, which only ever makes a sample too large)
			if at := s.pingAt.Swap(0); at != 0 {
				if d := time.Now().UnixNano() - at; d > 0 && (s.rtt.Load() == 0 || d < s.rtt.Load()) {
					s.rtt.Store(d)
				}
			}
		case cmdSYN:
			proto, target, src, ok := decodeOpen(p)
			if !ok {
				return
			}
			st := newStream(s, id)
			st.openProto, st.openAddr, st.openSrc = proto, target, src
			s.mu.Lock()
			s.streams[id] = st
			s.mu.Unlock()
			select {
			case s.accept <- st:
				go st.grantExtra()
			default:
				s.removeStream(id)
				go s.writeFrame(cmdRST, id, nil)
			}
		default:
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st == nil {
				continue
			}
			switch cmd {
			case cmdDATA:
				st.push(p)
			case cmdFIN:
				st.remoteFin()
			case cmdRST:
				st.abort()
				s.removeStream(id)
			case cmdWND:
				if len(p) == 4 {
					st.addCredit(int(binary.BigEndian.Uint32(p)))
				}
			default:
				return // protocol violation
			}
		}
	}
}

func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// ---- Stream ----

type Stream struct {
	id   uint32
	sess *Session

	openProto byte
	openAddr  string
	openSrc   string

	mu        sync.Mutex
	cond      *sync.Cond
	rbuf      [][]byte
	rEOF      bool // peer sent FIN
	reset     bool // aborted
	finSent   bool
	closed    bool
	sendWnd   int
	consumed  int
	window    int       // current receive window; grows up to sess.maxWindow
	lastGrant time.Time // when credit was last handed to the peer
}

func newStream(s *Session, id uint32) *Stream {
	st := &Stream{id: id, sess: s, sendWnd: initialWindow, window: s.window}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// grantExtra tells the peer about any receive window above the protocol default.
func (st *Stream) grantExtra() {
	if extra := st.sess.window - initialWindow; extra > 0 {
		st.sendCredit(extra)
	}
}

func (st *Stream) sendCredit(n int) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	st.sess.writeFrame(cmdWND, st.id, b[:])
}

func (st *Stream) push(p []byte) {
	st.mu.Lock()
	if !st.reset && !st.closed {
		st.rbuf = append(st.rbuf, p)
	}
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *Stream) remoteFin() {
	st.mu.Lock()
	st.rEOF = true
	done := st.finSent
	st.mu.Unlock()
	st.cond.Broadcast()
	if done {
		st.sess.removeStream(st.id)
	}
}

func (st *Stream) abort() {
	st.mu.Lock()
	st.reset = true
	st.rbuf = nil
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *Stream) addCredit(n int) {
	st.mu.Lock()
	st.sendWnd += n
	st.mu.Unlock()
	st.cond.Broadcast()
}

func (st *Stream) Read(p []byte) (int, error) {
	st.mu.Lock()
	for len(st.rbuf) == 0 && !st.rEOF && !st.reset && !st.closed {
		st.cond.Wait()
	}
	if st.reset || st.closed {
		st.mu.Unlock()
		return 0, errStreamClosed
	}
	if len(st.rbuf) == 0 {
		st.mu.Unlock()
		return 0, io.EOF
	}
	n := copy(p, st.rbuf[0])
	if n == len(st.rbuf[0]) {
		st.rbuf[0] = nil
		st.rbuf = st.rbuf[1:]
	} else {
		st.rbuf[0] = st.rbuf[0][n:]
	}
	st.consumed += n
	credit := 0
	if st.consumed >= st.window/2 {
		credit, st.consumed = st.consumed, 0
		// Self-tuning: half a window was read in under two round trips, so the
		// window, not the reader, is what holds this stream back — double it
		// (up to the session's limit) and hand the peer the extra credit too.
		// A slow reader never gets here, so its window (and the memory it can
		// pin) stays small.
		now := time.Now()
		if st.window < st.sess.maxWindow {
			if rtt := time.Duration(st.sess.rtt.Load()); rtt > 0 && !st.lastGrant.IsZero() && now.Sub(st.lastGrant) < 2*rtt {
				grow := st.window
				if st.window+grow > st.sess.maxWindow {
					grow = st.sess.maxWindow - st.window
				}
				st.window += grow
				credit += grow
			}
		}
		st.lastGrant = now
	}
	st.mu.Unlock()
	if credit > 0 {
		st.sendCredit(credit)
	}
	return n, nil
}

func (st *Stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		st.mu.Lock()
		for st.sendWnd <= 0 && !st.reset && !st.closed && !st.finSent {
			st.cond.Wait()
		}
		if st.reset || st.closed || st.finSent {
			st.mu.Unlock()
			return written, errStreamClosed
		}
		n := len(p)
		if n > st.sendWnd {
			n = st.sendWnd
		}
		if n > st.sess.frameSize {
			n = st.sess.frameSize
		}
		st.sendWnd -= n
		st.mu.Unlock()
		if err := st.sess.writeFrame(cmdDATA, st.id, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

// CloseWrite half-closes: the peer reads EOF, we can still read.
func (st *Stream) CloseWrite() error {
	st.mu.Lock()
	if st.finSent || st.reset || st.closed {
		st.mu.Unlock()
		return nil
	}
	st.finSent = true
	done := st.rEOF
	st.mu.Unlock()
	st.cond.Broadcast()
	err := st.sess.writeFrame(cmdFIN, st.id, nil)
	if done {
		st.sess.removeStream(st.id)
	}
	return err
}

func (st *Stream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	clean := st.rEOF && st.finSent
	needRST := !clean && !st.reset
	st.closed = true
	st.rbuf = nil
	st.mu.Unlock()
	st.cond.Broadcast()
	if needRST {
		st.sess.writeFrame(cmdRST, st.id, nil)
	}
	st.sess.removeStream(st.id)
	return nil
}
