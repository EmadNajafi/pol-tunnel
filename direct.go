package main

import (
	"crypto/ecdh"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// DirectConfig is a BackPack-style [direct] engine: a layer-3 point-to-point
// tunnel. A TUN interface on each side carries raw IP packets, which are
// encrypted (X25519 handshake + AES-256-GCM) and shipped over UDP to the peer.
type DirectConfig struct {
	Role       string // "server" (listens) or "client" (dials)
	BindAddr   string // server
	RemoteAddr string // client
	Token      string
	TunName    string
	LocalIP    string // this side's tunnel IP
	PeerIP     string // the other side's tunnel IP
	MTU        int
}

type directEngine struct {
	cfg  *DirectConfig
	tun  *tunDevice
	sock *net.UDPConn

	mu       sync.RWMutex
	keys     *directKeys   // active session keys
	replay   *replayWindow // anti-replay state for the active keys
	peerAddr *net.UDPAddr
	up       bool
	lastRecv time.Time // last authenticated DATA (incl. keepalives)
	lastSent time.Time

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
	tun, err := openTUN(cfg.TunName)
	if err != nil {
		return err
	}
	if err := tun.configure(cfg.LocalIP, cfg.PeerIP, cfg.MTU); err != nil {
		tun.Close()
		return err
	}
	logf("info", "direct: interface %s up (%s peer %s, mtu %d)", tun.name, cfg.LocalIP, cfg.PeerIP, cfg.MTU)

	e := &directEngine{cfg: cfg, tun: tun, seenInit: map[[x25519Len]byte]time.Time{}}
	if cfg.Role == "server" {
		addr, err := net.ResolveUDPAddr("udp", cfg.BindAddr)
		if err != nil {
			return err
		}
		if e.sock, err = net.ListenUDP("udp", addr); err != nil {
			return err
		}
		logf("info", "direct: waiting for peer on %s", cfg.BindAddr)
	} else {
		raddr, err := net.ResolveUDPAddr("udp", cfg.RemoteAddr)
		if err != nil {
			return err
		}
		if e.sock, err = net.ListenUDP("udp", &net.UDPAddr{Port: 0}); err != nil {
			return err
		}
		e.peerAddr = raddr
	}
	e.sock.SetReadBuffer(4 << 20)
	e.sock.SetWriteBuffer(4 << 20)

	go e.maintain()
	go e.tunToUDP()
	e.udpToTun() // blocks
	return nil
}

// sendData seals p (empty p = keepalive) with the active keys and sends it.
func (e *directEngine) sendData(p []byte) {
	e.mu.RLock()
	k, peer, up := e.keys, e.peerAddr, e.up
	e.mu.RUnlock()
	if !up || k == nil || peer == nil {
		return // tunnel not established yet: drop (IP will retransmit)
	}
	pkt := append([]byte{dirDATA}, k.send.seal(p)...)
	e.sock.WriteToUDP(pkt, peer)
	e.mu.Lock()
	e.lastSent = time.Now()
	e.mu.Unlock()
}

// maintain runs once a second: the client (re)sends INIT until established and
// re-handshakes when the peer goes silent; both sides send keepalives.
func (e *directEngine) maintain() {
	for {
		now := time.Now()
		e.mu.Lock()
		up, lastRecv, lastSent := e.up, e.lastRecv, e.lastSent
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
			initMsg, peer = e.initMsg, e.peerAddr
		}
		e.mu.Unlock()

		if initMsg != nil {
			e.sock.WriteToUDP(initMsg, peer)
		} else if up && now.Sub(lastSent) >= directKeepalive {
			e.sendData(nil)
		}
		time.Sleep(time.Second)
	}
}

func (e *directEngine) tunToUDP() {
	buf := make([]byte, 65535)
	for {
		n, err := e.tun.Read(buf)
		if err != nil {
			logf("error", "direct: tun read: %v", err)
			return
		}
		e.sendData(buf[:n])
	}
}

// openData authenticates a DATA packet against keys k and replay window rw.
func openData(k *directKeys, rw *replayWindow, sealed []byte) ([]byte, bool) {
	if k == nil {
		return nil, false
	}
	plain, err := k.recv.open(sealed)
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

func (e *directEngine) udpToTun() {
	buf := make([]byte, 65535)
	for {
		n, src, err := e.sock.ReadFromUDP(buf)
		if err != nil {
			logf("error", "direct: udp read: %v", err)
			return
		}
		if n < 1 {
			continue
		}
		switch buf[0] {
		case dirINIT:
			if e.cfg.Role == "server" {
				e.handleInit(buf[:n], src)
			}
		case dirRESP:
			if e.cfg.Role != "server" {
				e.handleResp(buf[:n])
			}
		case dirDATA:
			if n < 1+gcmNonce+gcmTag {
				continue
			}
			plain, ok := e.handleData(buf[1:n], src)
			if ok && len(plain) > 0 { // empty = keepalive
				e.tun.Write(plain)
			}
		}
	}
}

func (e *directEngine) handleData(sealed []byte, src *net.UDPAddr) ([]byte, bool) {
	e.mu.RLock()
	k, rw, pk, prw := e.keys, e.replay, e.pending, e.pendingReplay
	e.mu.RUnlock()

	plain, ok := openData(k, rw, sealed)
	promoted := false
	if !ok && pk != nil {
		// first packet under the keys of a fresh handshake: switch to them
		if plain, ok = openData(pk, prw, sealed); ok {
			promoted = true
		}
	}
	if !ok {
		logf("debug", "direct: dropped unauthenticated packet from %v", src)
		return nil, false
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
	if e.cfg.Role == "server" {
		// roaming: follow the peer's address, but only for authenticated, fresh packets
		e.peerAddr = src
	}
	e.lastRecv = time.Now()
	e.mu.Unlock()
	return plain, true
}

// server side: got an INIT, answer RESP and stage the new keys (responder).
// The active session is untouched until a DATA packet proves the initiator
// holds the new keys, so a replayed or stray INIT cannot break the tunnel.
func (e *directEngine) handleInit(msg []byte, src *net.UDPAddr) {
	now := time.Now()
	initPub, err := parseInit(e.cfg.Token, msg, now)
	if err != nil {
		logf("debug", "direct: bad INIT from %v: %v", src, err)
		return
	}
	var pub [x25519Len]byte
	copy(pub[:], initPub)

	e.mu.Lock()
	if pub == e.lastInitPub && e.lastResp != nil {
		// retransmitted INIT (our RESP was lost): resend the same RESP, keep keys
		resp := e.lastResp
		e.mu.Unlock()
		e.sock.WriteToUDP(resp, src)
		return
	}
	if _, seen := e.seenInit[pub]; seen {
		e.mu.Unlock()
		logf("debug", "direct: dropped replayed INIT from %v", src)
		return
	}
	for p, t := range e.seenInit {
		if now.Sub(t) > 2*initMaxSkew {
			delete(e.seenInit, p)
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
	e.sock.WriteToUDP(resp, src)
}

// client side: got RESP, derive keys (initiator) and confirm with a keepalive
// so the server switches to the new keys.
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
	e.up, e.lastRecv = true, time.Now()
	e.mu.Unlock()
	logf("info", "direct: tunnel established with %v", e.peerAddr)
	e.sendData(nil) // lets the server promote the new keys right away
}
