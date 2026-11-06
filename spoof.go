package main

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The spoof transport carries the tunnel over UDP with the ARQ reliability layer,
// optionally forging the source IP of outgoing packets (Linux, root). It is a
// point-to-point link between the two servers: every reply goes to the peer's
// configured real address, never to the (possibly spoofed) packet source.
//
// Outer datagram framing:  typ[1] connID[4] | payload
//
//	typ 0 = arq segment(s)   typ 1 = open (bootstrap a new connID on the server)
//
// Each connID is one reliable stream (an arqConn). The existing control/pool/mux
// logic sits on top unchanged, because arqConn is a net.Conn.

const (
	spTypeARQ  byte = 0
	spTypeOpen byte = 1
	spOuter         = 5 // typ + connID
)

// packetSender writes a finished UDP payload to a destination. The plain sender
// uses the shared socket; the spoof sender (Linux) forges the source address.
type packetSender interface {
	sendTo(payload []byte, dst *net.UDPAddr) error
	Close() error
}

type plainSender struct{ c *net.UDPConn }

func (p plainSender) sendTo(b []byte, dst *net.UDPAddr) error {
	_, err := p.c.WriteToUDP(b, dst)
	return err
}
func (p plainSender) Close() error { return nil }

// newSpoofSender returns a forging sender when src != "" (Linux only).
// newSpoofSender is defined per-OS in rawsend_linux.go / rawsend_other.go.

type spoofConn struct {
	arq *arqConn
	// learned source (used only when peerAddr is unset). Written by the read
	// loop and read by the ARQ sender goroutine, hence atomic.
	lastAddr atomic.Pointer[net.UDPAddr]
}

type spoofEndpoint struct {
	sock     *net.UDPConn
	sender   packetSender
	peerAddr *net.UDPAddr // fixed reply target (required when the peer forges its source)

	mu    sync.Mutex
	conns map[uint32]*spoofConn

	isServer bool
	accept   chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func newSpoofEndpoint(sock *net.UDPConn, sender packetSender, peer *net.UDPAddr, server bool) *spoofEndpoint {
	e := &spoofEndpoint{
		sock: sock, sender: sender, peerAddr: peer,
		conns:    map[uint32]*spoofConn{},
		isServer: server,
		accept:   make(chan net.Conn, 64),
		closed:   make(chan struct{}),
	}
	go e.readLoop()
	return e
}

func (e *spoofEndpoint) replyTarget(sc *spoofConn) *net.UDPAddr {
	if e.peerAddr != nil {
		return e.peerAddr
	}
	return sc.lastAddr.Load()
}

// newConn builds a spoofConn whose arqConn send callback frames + routes output.
func (e *spoofEndpoint) newConn(id uint32, peer *net.UDPAddr) *spoofConn {
	sc := &spoofConn{}
	sc.lastAddr.Store(peer)
	local := e.sock.LocalAddr()
	remote := net.Addr(peer)
	if e.peerAddr != nil {
		remote = e.peerAddr
	}
	sc.arq = newARQ(func(p []byte) error {
		dst := e.replyTarget(sc)
		if dst == nil {
			return errNoConn
		}
		frame := make([]byte, spOuter+len(p))
		frame[0] = spTypeARQ
		binary.BigEndian.PutUint32(frame[1:], id)
		copy(frame[spOuter:], p)
		return e.sender.sendTo(frame, dst)
	}, local, remote)
	return sc
}

func (e *spoofEndpoint) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := e.sock.ReadFromUDP(buf)
		if err != nil {
			e.Close()
			return
		}
		if n < spOuter {
			continue
		}
		typ := buf[0]
		id := binary.BigEndian.Uint32(buf[1:])
		payload := buf[spOuter:n]

		e.mu.Lock()
		sc := e.conns[id]
		if sc == nil {
			if !e.isServer {
				e.mu.Unlock()
				continue // client never auto-creates conns
			}
			sc = e.newConn(id, addr)
			e.conns[id] = sc
			e.mu.Unlock()
			select {
			case e.accept <- sc.arq:
			case <-e.closed:
				e.mu.Lock()
				delete(e.conns, id)
				e.mu.Unlock()
				continue
			}
			e.watch(id, sc)
		} else {
			if e.peerAddr == nil {
				sc.lastAddr.Store(addr)
			}
			e.mu.Unlock()
		}
		if typ == spTypeARQ {
			sc.arq.input(append([]byte(nil), payload...))
		}
	}
}

// watch removes a conn from the demux map once its arqConn closes.
func (e *spoofEndpoint) watch(id uint32, sc *spoofConn) {
	go func() {
		for {
			sc.arq.mu.Lock()
			closed := sc.arq.closed
			sc.arq.mu.Unlock()
			if closed {
				e.mu.Lock()
				delete(e.conns, id)
				e.mu.Unlock()
				return
			}
			select {
			case <-time.After(2 * time.Second):
			case <-e.closed:
				return
			}
		}
	}()
}

func (e *spoofEndpoint) Close() error {
	e.once.Do(func() {
		close(e.closed)
		e.sock.Close()
		e.sender.Close()
		e.mu.Lock()
		for _, sc := range e.conns {
			sc.arq.Close()
		}
		e.mu.Unlock()
	})
	return nil
}

// ---- server side: a TransportListener ----

func (e *spoofEndpoint) Accept() (net.Conn, error) {
	select {
	case c := <-e.accept:
		return c, nil
	case <-e.closed:
		return nil, net.ErrClosed
	}
}

func listenSpoof(cfg *ServerConfig) (TransportListener, error) {
	addr, err := net.ResolveUDPAddr("udp", cfg.BindAddr)
	if err != nil {
		return nil, err
	}
	sock, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	sock.SetReadBuffer(8 << 20)
	sock.SetWriteBuffer(8 << 20)

	var peer *net.UDPAddr
	if cfg.PeerAddr != "" {
		if peer, err = net.ResolveUDPAddr("udp", cfg.PeerAddr); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sender, err := buildSender(sock, cfg.SpoofSource, cfg.BindAddr)
	if err != nil {
		sock.Close()
		return nil, err
	}
	if cfg.SpoofSource != "" && peer == nil {
		sock.Close()
		return nil, errors.New("spoof: server forges its source, so it needs peer_addr (the client's real ip:port)")
	}
	logf("info", "spoof endpoint on %s (spoof_source=%q peer_addr=%q)", cfg.BindAddr, cfg.SpoofSource, cfg.PeerAddr)
	return newSpoofEndpoint(sock, sender, peer, true), nil
}

// ---- client side: a Dialer ----

func newSpoofDialer(cfg *ClientConfig) Dialer {
	var (
		once    sync.Once
		ep      *spoofEndpoint
		remote  *net.UDPAddr
		initErr error
	)
	start := func() {
		remote, initErr = net.ResolveUDPAddr("udp", cfg.RemoteAddr)
		if initErr != nil {
			return
		}
		sock, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			initErr = err
			return
		}
		sock.SetReadBuffer(8 << 20)
		sock.SetWriteBuffer(8 << 20)
		sender, err := buildSender(sock, cfg.SpoofSource, cfg.RemoteAddr)
		if err != nil {
			sock.Close()
			initErr = err
			return
		}
		ep = newSpoofEndpoint(sock, sender, remote, false)
	}

	return func(ctx context.Context) (net.Conn, error) {
		once.Do(start)
		if initErr != nil {
			return nil, initErr
		}
		id := rand.Uint32()
		ep.mu.Lock()
		if _, exists := ep.conns[id]; exists {
			id = rand.Uint32()
		}
		sc := ep.newConn(id, remote)
		ep.conns[id] = sc
		ep.mu.Unlock()
		ep.watch(id, sc)

		// bootstrap: tell the server to create this connID, retransmitting the
		// open until the server's first packet (the pol nonce) comes back.
		open := make([]byte, spOuter)
		open[0] = spTypeOpen
		binary.BigEndian.PutUint32(open[1:], id)
		go func() {
			for i := 0; i < 50; i++ {
				sc.arq.mu.Lock()
				got := sc.arq.rcvNext > 0 || len(sc.arq.rcvBuf) > 0 || sc.arq.closed
				sc.arq.mu.Unlock()
				if got {
					return
				}
				ep.sender.sendTo(open, remote)
				select {
				case <-time.After(100 * time.Millisecond):
				case <-ep.closed:
					return
				}
			}
		}()
		return sc.arq, nil
	}
}
