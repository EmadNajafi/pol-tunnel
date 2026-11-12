package main

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DirectConfig is a BackPack-style [direct] engine: a layer-3 point-to-point
// tunnel. A TUN interface on each side carries raw IP packets, which are
// encrypted (X25519 handshake + AES-256-GCM) and shipped to the peer over a
// datagram carrier.
//
// Carriers (per side — each side picks how its own outgoing packets look):
//
//	udp    plain UDP datagrams (default)
//	spoof  UDP with a forged source IPv4 (raw socket: Linux + root, and a
//	       datacenter without BCP38 egress filtering)
//	pck    hand-built TCP segments, no socket and no connection (Linux + root)
//	sni    pck preceded by a decoy TLS ClientHello naming an allowed domain
//	icmp   ICMP echo-reply messages (Linux + root)
//
// paths = N spreads the tunnel over N UDP sockets on consecutive ports, one
// inner flow per socket, so a per-flow rate limit on the route applies to
// each socket separately. Both ends must use the same N.
//
// auto_mtu measures the largest packet the route carries (authenticated
// padded probes, binary search) and sets the interface MTU to match.
type DirectConfig struct {
	Role       string // "server" (listens) or "client" (dials)
	BindAddr   string // server
	RemoteAddr string // client
	Token      string
	TunName    string
	LocalIP    string // this side's tunnel IP
	PeerIP     string // the other side's tunnel IP
	MTU        int    // interface MTU (the starting value when AutoMTU is on)

	Carrier     string // udp (default), spoof, pck, sni or icmp
	SpoofSource string // spoof: forge this source IPv4 on outgoing packets
	SpoofPeerIP string // server: the client's real IPv4, needed when the client forges its source
	SNIDomain   string // sni: the domain named in the decoy TLS ClientHello
	Paths       int    // number of sockets on consecutive ports (multipath); 1 = single socket
	AutoMTU     bool   // measure the route and set the interface MTU (needs a peer that answers probes)
	LogLevel    string // debug, info (default), warn or error
}

const (
	directMaxPaths = 16
	// directOverhead is what a DATA packet adds to the inner IP packet:
	// type[1] + nonce[12] + GCM tag[16].
	directOverhead = 1 + gcmNonce + gcmTag
)

// l3Device is the packet interface the engine reads from and writes to: the
// TUN device in production, a fake in tests.
type l3Device interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	setMTU(int) error
}

// directPath is one carrier transport. With paths = N there are N of them on
// consecutive ports (or, for icmp, consecutive identifiers).
type directPath struct {
	idx      int
	io       pathIO
	lastSent atomic.Int64 // unix nanos of the last packet sent on this path
	scratch  []byte       // decrypt buffer, used only by this path's read loop
}

type directEngine struct {
	cfg       *DirectConfig
	dev       l3Device
	paths     []*directPath
	spoofPeer net.IP // server: send to this IP instead of the (forged) source IP

	mu         sync.RWMutex
	keys       *directKeys   // active session keys
	replay     *replayWindow // anti-replay state for the active keys
	peers      []*net.UDPAddr
	up         bool
	lastRecvNs atomic.Int64 // unix nanos of the last authenticated DATA (incl. keepalives)
	mtu        int          // current interface MTU

	// client
	clientEph *ecdh.PrivateKey
	initMsg   []byte
	initAt    time.Time

	// server
	pending       *directKeys   // keys from the newest INIT, promoted on first DATA
	pendingReplay *replayWindow // anti-replay state for the pending keys
	seenInit      map[[x25519Len]byte]time.Time
	lastInitPub   [x25519Len]byte
	lastResp      []byte

	probeAcks chan uint32 // auto MTU: ids of acknowledged probes
	cleanup   func()      // carrier teardown (e.g. remove the RST firewall rule)
	closeOnce sync.Once
}

const (
	directKeepalive   = 10 * time.Second // empty DATA packet when idle (also keeps NAT open)
	directDeadAfter   = 45 * time.Second // client re-handshakes after this much silence
	directInitRefresh = 30 * time.Second // client makes a fresh INIT (new key + timestamp)
)

func RunDirect(cfg *DirectConfig) error {
	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}
	if cfg.Paths < 1 {
		cfg.Paths = 1
	}
	tun, err := openTUN(cfg.TunName)
	if err != nil {
		return err
	}
	if err := tun.configure(cfg.LocalIP, cfg.PeerIP, cfg.MTU); err != nil {
		tun.Close()
		return err
	}
	logf("info", "direct: interface %s up (%s peer %s, mtu %d)", tun.name, cfg.LocalIP, cfg.PeerIP, cfg.MTU)

	paths, peers, cleanup, err := openDirectPaths(cfg)
	if err != nil {
		tun.Close()
		return err
	}
	e, err := newDirectEngine(cfg, tun, paths, peers)
	if err != nil {
		for _, p := range paths {
			p.io.Close()
		}
		cleanup()
		tun.Close()
		return err
	}
	e.cleanup = cleanup
	defer e.close()
	// A systemctl stop (SIGTERM) must still run cleanup, e.g. remove the RST
	// firewall rule the pck/sni carriers add; otherwise it would leak.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		e.close()
		os.Exit(0)
	}()
	if cfg.Role == "server" {
		logf("info", "direct: waiting for peer on %s (carrier %s, %d path(s))", cfg.BindAddr, cfg.Carrier, cfg.Paths)
	} else {
		logf("info", "direct: dialing %s (carrier %s, %d path(s))", cfg.RemoteAddr, cfg.Carrier, cfg.Paths)
	}
	return e.run()
}

// openDirectSockets opens one UDP socket per path. The server listens on
// bind port, bind port+1, …; the client uses ephemeral local ports and sends
// path i to remote port + i.
func openDirectSockets(cfg *DirectConfig) ([]*net.UDPConn, []*net.UDPAddr, error) {
	n := cfg.Paths
	var socks []*net.UDPConn
	fail := func(err error) ([]*net.UDPConn, []*net.UDPAddr, error) {
		for _, s := range socks {
			s.Close()
		}
		return nil, nil, err
	}
	peers := make([]*net.UDPAddr, n)
	if cfg.Role == "server" {
		addr, err := net.ResolveUDPAddr("udp", cfg.BindAddr)
		if err != nil {
			return fail(err)
		}
		for i := 0; i < n; i++ {
			a := &net.UDPAddr{IP: addr.IP, Port: addr.Port + i, Zone: addr.Zone}
			s, err := net.ListenUDP("udp", a)
			if err != nil {
				return fail(fmt.Errorf("path %d: %w", i, err))
			}
			socks = append(socks, s)
		}
		return socks, peers, nil
	}
	raddr, err := net.ResolveUDPAddr("udp", cfg.RemoteAddr)
	if err != nil {
		return fail(err)
	}
	for i := 0; i < n; i++ {
		s, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			return fail(fmt.Errorf("path %d: %w", i, err))
		}
		socks = append(socks, s)
		peers[i] = &net.UDPAddr{IP: raddr.IP, Port: raddr.Port + i, Zone: raddr.Zone}
	}
	return socks, peers, nil
}

// newDirectEngine builds the engine over ready per-path transports. peers holds
// the fixed send target of each path (client) or nils (server, which learns
// them from authenticated packets).
func newDirectEngine(cfg *DirectConfig, dev l3Device, paths []*directPath, peers []*net.UDPAddr) (*directEngine, error) {
	if cfg.Carrier == "" {
		cfg.Carrier = "udp"
	}
	e := &directEngine{
		cfg:       cfg,
		dev:       dev,
		paths:     paths,
		peers:     peers,
		mtu:       cfg.MTU,
		seenInit:  map[[x25519Len]byte]time.Time{},
		probeAcks: make(chan uint32, 16),
	}
	if cfg.SpoofPeerIP != "" {
		if e.spoofPeer = net.ParseIP(cfg.SpoofPeerIP).To4(); e.spoofPeer == nil {
			return nil, fmt.Errorf("spoof_peer_ip %q is not an IPv4 address", cfg.SpoofPeerIP)
		}
	}
	return e, nil
}

// newDirectEngineUDP builds a udp/spoof engine straight from UDP sockets (used
// by tests and by the udp/spoof path of RunDirect through openDirectPaths).
func newDirectEngineUDP(cfg *DirectConfig, dev l3Device, socks []*net.UDPConn, peers []*net.UDPAddr) (*directEngine, error) {
	paths, err := udpPaths(cfg, socks)
	if err != nil {
		return nil, err
	}
	return newDirectEngine(cfg, dev, paths, peers)
}

// run starts the engine and blocks until a socket or the device fails.
func (e *directEngine) run() error {
	errc := make(chan error, len(e.paths)+1)
	go e.maintain()
	if e.cfg.AutoMTU {
		go e.autoMTULoop()
	}
	go func() { errc <- e.devToNet() }()
	for _, p := range e.paths {
		go func(p *directPath) { errc <- e.readLoop(p) }(p)
	}
	return <-errc
}

func (e *directEngine) close() {
	e.closeOnce.Do(func() {
		for _, p := range e.paths {
			p.io.Close()
		}
		if e.cleanup != nil {
			e.cleanup()
		}
	})
}

// targetLocked returns the send target for path i, falling back to any path
// whose peer address is known (the server learns path addresses one by one).
// Caller holds e.mu.
func (e *directEngine) targetLocked(i int) (*net.UDPAddr, int) {
	if i < len(e.peers) && e.peers[i] != nil {
		return e.peers[i], i
	}
	for j, a := range e.peers {
		if a != nil {
			return a, j
		}
	}
	return nil, 0
}

// replyAddr is where packets for a peer seen at src go. When the client forges
// its source IP, the server sends to its real IP (spoof_peer_ip) instead; the
// port is kept, since the forging sender uses its socket's real port.
func (e *directEngine) replyAddr(src *net.UDPAddr) *net.UDPAddr {
	if e.spoofPeer != nil {
		return &net.UDPAddr{IP: e.spoofPeer, Port: src.Port}
	}
	return src
}

func (e *directEngine) sendOn(p *directPath, pkt []byte, dst *net.UDPAddr) {
	if err := p.io.send(pkt, dst); err != nil {
		logf("debug", "direct: path %d send: %v", p.idx, err)
	}
	p.lastSent.Store(time.Now().UnixNano())
}

var directPktPool = sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }}

// sendData seals p (empty p = keepalive) with the active keys and sends it on
// the given path.
func (e *directEngine) sendData(p []byte, path int) {
	e.mu.RLock()
	k, up := e.keys, e.up
	dst, pi := e.targetLocked(path)
	e.mu.RUnlock()
	if !up || k == nil || dst == nil {
		return // tunnel not established yet: drop (IP will retransmit)
	}
	// one pooled buffer per packet instead of two allocations (the carriers
	// send synchronously and keep nothing)
	bp := directPktPool.Get().(*[]byte)
	pkt := k.send.sealAppend(append((*bp)[:0], dirDATA), p)
	e.sendOn(e.paths[pi], pkt, dst)
	*bp = pkt[:0]
	directPktPool.Put(bp)
}

// maintain runs once a second: the client (re)sends INIT until established and
// re-handshakes when the peer goes silent; both sides send keepalives on every
// idle path (so each path's NAT mapping and learned address stay fresh).
func (e *directEngine) maintain() {
	for {
		now := time.Now()
		e.mu.Lock()
		up, lastRecv := e.up, time.Unix(0, e.lastRecvNs.Load())
		if e.cfg.Role != "server" && up && now.Sub(lastRecv) > directDeadAfter {
			logf("warn", "direct: no packets from peer for %v, re-handshaking", directDeadAfter)
			e.up, e.keys, e.replay, e.clientEph, e.initMsg = false, nil, nil, nil, nil
			up = false
		}
		var initMsg []byte
		var peer *net.UDPAddr
		if e.cfg.Role != "server" && !up {
			if e.initMsg == nil || now.Sub(e.initAt) > directInitRefresh {
				eph, err := genEphemeral()
				if err != nil {
					e.mu.Unlock()
					logf("error", "direct: %v", err)
					time.Sleep(time.Second)
					continue
				}
				e.clientEph, e.initMsg, e.initAt = eph, makeInit(e.cfg.Token, eph.PublicKey().Bytes(), now), now
			}
			initMsg, peer = e.initMsg, e.peers[0]
		}
		e.mu.Unlock()

		if initMsg != nil {
			e.sendOn(e.paths[0], initMsg, peer)
		} else if up {
			for _, p := range e.paths {
				if now.Sub(time.Unix(0, p.lastSent.Load())) >= directKeepalive {
					e.sendData(nil, p.idx)
				}
			}
		}
		time.Sleep(time.Second)
	}
}

func (e *directEngine) devToNet() error {
	buf := make([]byte, 65535)
	n := len(e.paths)
	for {
		k, err := e.dev.Read(buf)
		if err != nil {
			logf("error", "direct: tun read: %v", err)
			return err
		}
		e.sendData(buf[:k], flowPath(buf[:k], n))
	}
}

// flowPath picks the path for an inner IP packet: a hash of its addresses,
// protocol and (TCP/UDP) ports, so one flow always takes one path and is never
// reordered across paths.
func flowPath(pkt []byte, n int) int {
	if n <= 1 || len(pkt) < 20 {
		return 0
	}
	var proto byte
	var addrs, l4 []byte
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return 0
		}
		proto, addrs = pkt[9], pkt[12:20]
		// fragments: only the first carries ports, so leave ports out for all of them
		if binary.BigEndian.Uint16(pkt[6:8])&0x3fff == 0 {
			l4 = pkt[ihl:]
		}
	case 6:
		if len(pkt) < 40 {
			return 0
		}
		proto, addrs, l4 = pkt[6], pkt[8:40], pkt[40:]
	default:
		return 0
	}
	h := uint32(2166136261) // FNV-1a
	mix := func(b []byte) {
		for _, c := range b {
			h ^= uint32(c)
			h *= 16777619
		}
	}
	mix(addrs)
	mix([]byte{proto})
	if (proto == 6 || proto == 17) && len(l4) >= 4 {
		mix(l4[:4])
	}
	return int(h % uint32(n))
}

// openData authenticates a DATA packet against keys k and replay window rw.
// openData authenticates and decrypts into dst[:0] (nil = allocate).
func openData(k *directKeys, rw *replayWindow, sealed, dst []byte) ([]byte, bool) {
	if k == nil {
		return nil, false
	}
	plain, err := k.recv.openAppend(dst[:0], sealed)
	if err != nil {
		return nil, false
	}
	// the counter lives in the authenticated nonce (sealed[4:12]); drop replays
	ctr := binary.BigEndian.Uint64(sealed[4:gcmNonce])
	if rw != nil && !rw.check(ctr) {
		logf("debug", "direct: dropped replayed/old packet %d", ctr)
		return nil, false
	}
	return plain, true
}

func (e *directEngine) readLoop(p *directPath) error {
	buf := make([]byte, 65535)
	for {
		n, src, err := p.io.recv(buf)
		if err != nil {
			logf("error", "direct: read (path %d): %v", p.idx, err)
			return err
		}
		if n < 1 {
			continue
		}
		switch buf[0] {
		case dirINIT:
			if e.cfg.Role == "server" {
				e.handleInit(buf[:n], src, p)
			}
		case dirRESP:
			if e.cfg.Role != "server" {
				e.handleResp(buf[:n])
			}
		case dirDATA:
			if n < directOverhead {
				continue
			}
			if plain, ok := e.handleData(buf[1:n], src, p.idx); ok {
				e.deliver(plain, p.idx)
			}
		}
	}
}

// deliver hands an authenticated payload to the device, or to the control
// handler. An IP packet starts with version 4 or 6, never 0x00, so a leading
// zero byte marks an in-tunnel control message (older peers that do not know
// them hand them to the kernel, which drops them as invalid IP).
func (e *directEngine) deliver(plain []byte, path int) {
	switch {
	case len(plain) == 0: // keepalive
	case plain[0] == ctlMarker:
		e.handleControl(plain, path)
	default:
		e.dev.Write(plain)
	}
}

func (e *directEngine) handleData(sealed []byte, src *net.UDPAddr, path int) ([]byte, bool) {
	e.mu.RLock()
	k, rw, pk, prw := e.keys, e.replay, e.pending, e.pendingReplay
	var curPeer *net.UDPAddr
	if path < len(e.peers) {
		curPeer = e.peers[path]
	}
	e.mu.RUnlock()

	// each path is read by one goroutine, so it can decrypt into its own buffer
	var scratch []byte
	if path < len(e.paths) {
		if e.paths[path].scratch == nil {
			e.paths[path].scratch = make([]byte, 0, 65535)
		}
		scratch = e.paths[path].scratch
	}
	plain, ok := openData(k, rw, sealed, scratch)
	promoted := false
	if !ok && pk != nil {
		// first packet under the keys of a fresh handshake: switch to them
		if plain, ok = openData(pk, prw, sealed, scratch); ok {
			promoted = true
		}
	}
	if !ok {
		logf("debug", "direct: dropped unauthenticated packet from %v", src)
		return nil, false
	}
	e.lastRecvNs.Store(time.Now().UnixNano())

	// The common packet changes nothing but the timestamp above, so it takes
	// no write lock (every packet used to, and the sending side contends on
	// the same mutex for every packet it sends). Only a re-key or a peer that
	// moved needs it.
	moved := false
	if e.cfg.Role == "server" && path < len(e.peers) {
		wantIP := src.IP
		if e.spoofPeer != nil {
			wantIP = e.spoofPeer
		}
		moved = curPeer == nil || curPeer.Port != src.Port || !curPeer.IP.Equal(wantIP)
	}
	if !promoted && !moved {
		return plain, true
	}
	e.mu.Lock()
	if promoted && e.pending == pk {
		e.keys, e.replay = pk, prw
		e.pending, e.pendingReplay = nil, nil
		if !e.up {
			logf("info", "direct: tunnel established with %v", src)
		} else {
			logf("info", "direct: peer %v re-keyed", src)
		}
		e.up = true
	}
	if moved {
		// roaming: follow the peer's address, but only for authenticated, fresh packets
		e.peers[path] = e.replyAddr(src)
	}
	e.mu.Unlock()
	return plain, true
}

// server side: got an INIT, answer RESP and stage the new keys (responder).
// The active session is untouched until a DATA packet proves the initiator
// holds the new keys, so a replayed or stray INIT cannot break the tunnel.
func (e *directEngine) handleInit(msg []byte, src *net.UDPAddr, p *directPath) {
	now := time.Now()
	initPub, err := parseInit(e.cfg.Token, msg, now)
	if err != nil {
		logf("debug", "direct: bad INIT from %v: %v", src, err)
		return
	}
	var pub [x25519Len]byte
	copy(pub[:], initPub)
	dst := e.replyAddr(src)

	e.mu.Lock()
	if pub == e.lastInitPub && e.lastResp != nil {
		// retransmitted INIT (our RESP was lost): resend the same RESP, keep keys
		resp := e.lastResp
		e.mu.Unlock()
		e.sendOn(p, resp, dst)
		return
	}
	if _, seen := e.seenInit[pub]; seen {
		e.mu.Unlock()
		logf("debug", "direct: dropped replayed INIT from %v", src)
		return
	}
	for k, t := range e.seenInit {
		if now.Sub(t) > 2*initMaxSkew {
			delete(e.seenInit, k)
		}
	}
	e.seenInit[pub] = now
	e.mu.Unlock()

	eph, err := genEphemeral()
	if err != nil {
		return
	}
	ss, err := sharedSecret(eph, initPub)
	if err != nil {
		return
	}
	keys, err := deriveKeys(e.cfg.Token, ss, false)
	if err != nil {
		return
	}
	resp := makeResp(e.cfg.Token, initPub, eph.PublicKey().Bytes())

	e.mu.Lock()
	e.pending, e.pendingReplay = keys, &replayWindow{}
	e.lastInitPub, e.lastResp = pub, resp
	e.mu.Unlock()
	e.sendOn(p, resp, dst)
}

// client side: got RESP, derive keys (initiator) and confirm with a keepalive
// on every path, so the server switches to the new keys and learns each
// path's address.
func (e *directEngine) handleResp(msg []byte) {
	e.mu.RLock()
	eph, up := e.clientEph, e.up
	e.mu.RUnlock()
	if eph == nil || up {
		return // no handshake in progress (or a duplicate RESP)
	}
	respPub, err := parseResp(e.cfg.Token, eph.PublicKey().Bytes(), msg)
	if err != nil {
		logf("debug", "direct: bad RESP: %v", err)
		return
	}
	ss, err := sharedSecret(eph, respPub)
	if err != nil {
		return
	}
	keys, err := deriveKeys(e.cfg.Token, ss, true)
	if err != nil {
		return
	}
	e.mu.Lock()
	if e.up || e.clientEph != eph {
		e.mu.Unlock()
		return
	}
	e.keys, e.replay = keys, &replayWindow{}
	e.up = true
	e.lastRecvNs.Store(time.Now().UnixNano())
	e.mu.Unlock()
	logf("info", "direct: tunnel established with %v", e.peers[0])
	for _, p := range e.paths {
		e.sendData(nil, p.idx)
	}
}
