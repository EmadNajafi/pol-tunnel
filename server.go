package main

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// Server is the Iran side: it owns the public ports and waits for the client
// (kharej side) to dial in. Visitors hit a public port, and their traffic is
// sent to the client over a pooled data conn (tcp/ws) or a mux stream (*mux).
type Server struct {
	cfg   *ServerConfig
	ports []PortMap
	stats *Stats

	// non-mux mode
	ctlMu sync.Mutex
	ctl   net.Conn
	pool  chan net.Conn

	// mux mode
	sessMu   sync.Mutex
	sessions []*Session
	rr       int
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	ports, err := ParsePorts(cfg.Ports)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, ports: ports, stats: NewStats(), pool: make(chan net.Conn, cfg.ChannelSize)}, nil
}

func (s *Server) Run() error {
	ln, err := Listen(s.cfg)
	if err != nil {
		return err
	}
	logf("info", "server listening on %s (transport=%s)", s.cfg.BindAddr, s.cfg.Transport)

	for _, pm := range s.ports {
		if err := s.listenTCP(pm); err != nil {
			return err
		}
		if s.cfg.AcceptUDP {
			if err := s.listenUDP(pm); err != nil {
				return err
			}
		}
	}
	s.stats.Info = func() map[string]any {
		s.sessMu.Lock()
		n := len(s.sessions)
		s.sessMu.Unlock()
		s.ctlMu.Lock()
		connected := s.ctl != nil || n > 0
		s.ctlMu.Unlock()
		return map[string]any{"transport": s.cfg.Transport, "client_connected": connected, "pooled_conns": len(s.pool), "mux_sessions": n}
	}
	s.stats.Serve(s.cfg.WebPort)
	if !isMux(s.cfg.Transport) {
		go s.poolPinger()
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleTunnelConn(c)
	}
}

func (s *Server) handleTunnelConn(c net.Conn) {
	kind, err := serverHandshake(c, s.cfg.Token)
	if err != nil {
		logf("debug", "handshake from %s failed: %v", c.RemoteAddr(), err)
		time.Sleep(time.Second) // don't give probers a fast oracle
		c.Close()
		return
	}
	mux := isMux(s.cfg.Transport)
	switch {
	case kind == connMux && mux:
		sess := NewSession(c, s.cfg.MuxFrameSize, s.cfg.MuxWindow, s.cfg.Heartbeat)
		s.sessMu.Lock()
		s.sessions = append(s.sessions, sess)
		total := len(s.sessions)
		s.sessMu.Unlock()
		logf("info", "mux session up from %s (%d total)", c.RemoteAddr(), total)
		<-sess.Done()
		s.sessMu.Lock()
		for i, x := range s.sessions {
			if x == sess {
				s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
				break
			}
		}
		s.sessMu.Unlock()
		logf("info", "mux session from %s closed", c.RemoteAddr())
	case kind == connControl && !mux:
		s.runControl(c)
	case kind == connData && !mux:
		select {
		case s.pool <- c:
		default:
			logf("warn", "data pool full (channel_size=%d), dropping conn", cap(s.pool))
			c.Close()
		}
	default:
		logf("warn", "client %s uses a different transport mode, closing", c.RemoteAddr())
		c.Close()
	}
}

// ---- control channel (non-mux) ----

func (s *Server) runControl(c net.Conn) {
	s.ctlMu.Lock()
	if s.ctl != nil {
		logf("warn", "new control channel from %s replaces the old one", c.RemoteAddr())
		s.ctl.Close()
	}
	s.ctl = c
	s.ctlMu.Unlock()
	logf("info", "client connected from %s", c.RemoteAddr())

	hb := s.cfg.Heartbeat
	cfgMsg := []byte{ctlConfig, 0, 0}
	binary.BigEndian.PutUint16(cfgMsg[1:], uint16(hb/time.Second))
	s.ctlWrite(c, cfgMsg)

	done := make(chan struct{})
	go func() { // heartbeat sender
		t := time.NewTicker(hb)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if s.ctlWrite(c, []byte{ctlHeartbeat}) != nil {
					c.Close()
					return
				}
			}
		}
	}()
	b := make([]byte, 1)
	for {
		c.SetReadDeadline(time.Now().Add(3 * hb))
		if _, err := io.ReadFull(c, b); err != nil {
			break
		}
	}
	close(done)
	c.Close()
	s.ctlMu.Lock()
	if s.ctl == c {
		s.ctl = nil
	}
	s.ctlMu.Unlock()
	logf("warn", "control channel from %s lost", c.RemoteAddr())
}

func (s *Server) ctlWrite(c net.Conn, b []byte) error {
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.Write(b)
	return err
}

func (s *Server) requestConns(n int) {
	s.ctlMu.Lock()
	c := s.ctl
	s.ctlMu.Unlock()
	if c == nil {
		return
	}
	msg := []byte{ctlNeed, 0, 0}
	binary.BigEndian.PutUint16(msg[1:], uint16(n))
	s.ctlWrite(c, msg)
}

// poolPinger keeps idle pooled conns warm and weeds out dead ones.
func (s *Server) poolPinger() {
	t := time.NewTicker(s.cfg.Heartbeat)
	defer t.Stop()
	for range t.C {
		for i, n := 0, len(s.pool); i < n; i++ {
			var c net.Conn
			select {
			case c = <-s.pool:
			default:
			}
			if c == nil {
				break
			}
			c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := c.Write([]byte{protoPing})
			c.SetWriteDeadline(time.Time{})
			if err != nil {
				c.Close()
				continue
			}
			select {
			case s.pool <- c:
			default:
				c.Close()
			}
		}
	}
}

func (s *Server) takeDataConn() (net.Conn, error) {
	select {
	case c := <-s.pool:
		return c, nil
	default:
	}
	s.requestConns(1) // ask the client for exactly one more (1:1, no request storms)
	select {
	case c := <-s.pool:
		return c, nil
	case <-time.After(s.cfg.DialTimeout):
		return nil, errNoConn
	}
}

// open returns a tunnel stream to the client that will forward to target.
func (s *Server) open(proto byte, target string) (io.ReadWriteCloser, error) {
	if isMux(s.cfg.Transport) {
		s.sessMu.Lock()
		var best *Session
		if n := len(s.sessions); n > 0 {
			// round robin start, then pick the least loaded session
			s.rr++
			for i := 0; i < n; i++ {
				x := s.sessions[(s.rr+i)%n]
				if !x.IsClosed() && (best == nil || x.NumStreams() < best.NumStreams()) {
					best = x
				}
			}
		}
		s.sessMu.Unlock()
		if best == nil {
			return nil, errNoConn
		}
		return best.Open(proto, target)
	}
	for attempt := 0; attempt < 3; attempt++ {
		c, err := s.takeDataConn()
		if err != nil {
			return nil, err
		}
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		err = writeOpenHeader(c, proto, target)
		c.SetWriteDeadline(time.Time{})
		if err == nil {
			return c, nil
		}
		c.Close()
	}
	return nil, errNoConn
}

// ---- public ports ----

func (s *Server) listenTCP(pm PortMap) error {
	ln, err := net.Listen("tcp", pm.Listen)
	if err != nil {
		return err
	}
	st := s.stats.Get(pm.Listen + "/tcp")
	logf("info", "forwarding tcp %s -> client %s", pm.Listen, pm.Target)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				logf("error", "accept %s: %v", pm.Listen, err)
				time.Sleep(time.Second)
				continue
			}
			tuneTCP(c, &s.cfg.Common)
			go func() {
				t, err := s.open(protoTCP, pm.Target)
				if err != nil {
					logf("warn", "%s: %v", pm.Listen, err)
					c.Close()
					return
				}
				pipe(c, t, st)
			}()
		}
	}()
	return nil
}

type udpPeer struct {
	stream io.ReadWriteCloser
	out    chan []byte
	last   time.Time
}

func (s *Server) listenUDP(pm PortMap) error {
	laddr, err := net.ResolveUDPAddr("udp", pm.Listen)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	st := s.stats.Get(pm.Listen + "/udp")
	logf("info", "forwarding udp %s -> client %s", pm.Listen, pm.Target)
	var mu sync.Mutex
	peers := map[string]*udpPeer{}

	go func() { // idle reaper
		for range time.Tick(s.cfg.UDPIdle / 2) {
			mu.Lock()
			for k, p := range peers {
				if time.Since(p.last) > s.cfg.UDPIdle {
					p.stream.Close()
					close(p.out)
					delete(peers, k)
					st.Active.Add(-1)
				}
			}
			mu.Unlock()
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := uc.ReadFromUDP(buf)
			if err != nil {
				logf("error", "udp %s: %v", pm.Listen, err)
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			key := addr.String()
			mu.Lock()
			p := peers[key]
			if p == nil {
				t, err := s.open(protoUDP, pm.Target)
				if err != nil {
					mu.Unlock()
					logf("warn", "udp %s: %v", pm.Listen, err)
					continue
				}
				p = &udpPeer{stream: t, out: make(chan []byte, s.cfg.ChannelSize)}
				peers[key] = p
				st.Active.Add(1)
				st.Total.Add(1)
				go func(p *udpPeer, addr *net.UDPAddr, key string) { // tunnel -> visitor
					rb := make([]byte, 65535)
					for {
						n, err := readDatagram(p.stream, rb)
						if err != nil {
							p.stream.Close()
							mu.Lock()
							if peers[key] == p {
								delete(peers, key)
								close(p.out)
								st.Active.Add(-1)
							}
							mu.Unlock()
							return
						}
						st.BytesOut.Add(int64(n))
						uc.WriteToUDP(rb[:n], addr)
					}
				}(p, addr, key)
				go func(p *udpPeer) { // visitor -> tunnel
					for pkt := range p.out {
						if writeDatagram(p.stream, pkt) != nil {
							p.stream.Close()
							return
						}
						st.BytesIn.Add(int64(len(pkt)))
					}
				}(p)
			}
			p.last = time.Now()
			select {
			case p.out <- pkt:
			default: // queue full: drop, like a real UDP link would
			}
			mu.Unlock()
		}
	}()
	return nil
}
