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

	mu        sync.RWMutex
	keys      *directKeys
	replay    *replayWindow
	peerAddr  *net.UDPAddr
	up        bool
	clientEph *ecdh.PrivateKey
}

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

	e := &directEngine{cfg: cfg, tun: tun}
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
		go e.clientHandshakeLoop(raddr)
	}
	e.sock.SetReadBuffer(4 << 20)
	e.sock.SetWriteBuffer(4 << 20)

	go e.tunToUDP()
	e.udpToTun() // blocks
	return nil
}

func (e *directEngine) setKeys(k *directKeys, peer *net.UDPAddr) {
	e.mu.Lock()
	e.keys = k
	e.replay = &replayWindow{} // fresh anti-replay state per handshake
	if peer != nil {
		e.peerAddr = peer
	}
	wasUp := e.up
	e.up = true
	e.mu.Unlock()
	if !wasUp {
		logf("info", "direct: tunnel established with %v", peer)
	}
}

// client: send INIT until the server answers with RESP.
func (e *directEngine) clientHandshakeLoop(peer *net.UDPAddr) {
	eph, err := genEphemeral()
	if err != nil {
		logf("error", "direct: %v", err)
		return
	}
	e.mu.Lock()
	e.clientEph = eph
	e.mu.Unlock()
	initMsg := makeInit(e.cfg.Token, eph.PublicKey().Bytes())
	for {
		e.mu.RLock()
		up := e.up
		e.mu.RUnlock()
		if up {
			return
		}
		e.sock.WriteToUDP(initMsg, peer)
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
		e.mu.RLock()
		k, peer, up := e.keys, e.peerAddr, e.up
		e.mu.RUnlock()
		if !up || k == nil || peer == nil {
			continue // tunnel not established yet: drop (IP will retransmit)
		}
		pkt := append([]byte{dirDATA}, k.send.seal(buf[:n])...)
		e.sock.WriteToUDP(pkt, peer)
	}
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
			e.handleInit(buf[:n], src)
		case dirRESP:
			e.handleResp(buf[:n])
		case dirDATA:
			e.mu.RLock()
			k, rw := e.keys, e.replay
			e.mu.RUnlock()
			if k == nil || n < 1+gcmNonce+gcmTag {
				continue
			}
			plain, err := k.recv.open(buf[1:n])
			if err != nil {
				logf("debug", "direct: decrypt failed: %v", err)
				continue
			}
			// the counter lives in the authenticated nonce (sealed[4:12]); drop replays
			ctr := binary.BigEndian.Uint64(buf[1+4 : 1+gcmNonce])
			if rw != nil && !rw.check(ctr) {
				logf("debug", "direct: dropped replayed/old packet %d", ctr)
				continue
			}
			e.tun.Write(plain)
		}
	}
}

// server side: got an INIT, answer RESP and derive keys (responder).
func (e *directEngine) handleInit(msg []byte, src *net.UDPAddr) {
	initPub, err := parseInit(e.cfg.Token, msg)
	if err != nil {
		logf("debug", "direct: bad INIT from %v: %v", src, err)
		return
	}
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
	e.sock.WriteToUDP(makeResp(e.cfg.Token, initPub, eph.PublicKey().Bytes()), src)
	e.setKeys(keys, src)
}

// client side: got RESP, derive keys (initiator).
func (e *directEngine) handleResp(msg []byte) {
	e.mu.RLock()
	eph := e.clientEph
	e.mu.RUnlock()
	if eph == nil {
		return
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
	e.setKeys(keys, nil)
}
