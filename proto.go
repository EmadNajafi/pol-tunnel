package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Wire protocol (all integers big-endian)
//
// Handshake on every transport connection (rathole-style challenge/response,
// so the token itself never crosses the wire):
//
//	S -> C : "POL1" | nonce[32]
//	C -> S : kind[1] | HMAC-SHA256(token, "pol-c" | nonce | kind)[32]
//	S -> C : HMAC-SHA256(token, "pol-s" | nonce | kind)[32]      (mutual auth)
//
// A server that sees a bad MAC just stays silent and closes, so probes learn nothing.
//
// kind = connControl : control channel (heartbeats, "need N data conns")
//        connData    : one pooled data connection (non-mux transports)
//        connMux     : one multiplexed session (mux transports)
//
// Open header (server -> client, at the start of a data conn or a mux stream):
//
//	proto[1] (1=tcp 2=udp) | addrLen[1] | addr
//
// A data conn may first receive any number of ping bytes (0x00) while idle in the pool.

const (
	connControl byte = 1
	connData    byte = 2
	connMux     byte = 3

	protoPing byte = 0
	protoTCP  byte = 1
	protoUDP  byte = 2

	ctlHeartbeat byte = 1 // S -> C, C echoes it back
	ctlNeed      byte = 2 // S -> C, followed by uint16 count
	ctlConfig    byte = 3 // S -> C, first message: uint16 heartbeat seconds
)

var magic = []byte("POL2")

var errAuth = errors.New("authentication failed")

const encFlag = 0x01 // bit0 in the flags byte: this side wants encryption

// hsMac binds the whole handshake transcript (nonce, kind, both flag bytes,
// both ephemeral public keys) so a MITM cannot alter any of it without the token.
func hsMac(token, label string, nonce []byte, kind, sFlags, cFlags byte, sPub, cPub []byte) []byte {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte(label))
	h.Write(nonce)
	h.Write([]byte{kind, sFlags, cFlags})
	h.Write(sPub)
	h.Write(cPub)
	return h.Sum(nil)
}

// Handshake (POL2), on every transport connection:
//
//	S->C : "POL2" | sFlags[1] | sEphPub[32] | nonce[32]
//	C->S : kind[1] | cFlags[1] | cEphPub[32] | HMAC(token, "pol-c" | transcript)
//	S->C : HMAC(token, "pol-s" | transcript)
//
// The token is proven both ways without crossing the wire. When both flags set
// encFlag, the two ephemeral X25519 keys yield a session key (forward secrecy)
// and the returned conn is wrapped in AES-256-GCM. A wrong token => the server
// stays silent and closes, so probes learn nothing.

// serverHandshake authenticates an incoming connection, negotiates encryption,
// and returns its kind plus the conn to use (AEAD-wrapped if negotiated).
func serverHandshake(c net.Conn, token string, encrypt bool) (byte, net.Conn, error) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	eph, err := genEphemeral()
	if err != nil {
		return 0, nil, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return 0, nil, err
	}
	sFlags := byte(0)
	if encrypt {
		sFlags |= encFlag
	}
	sPub := eph.PublicKey().Bytes()
	msg := append([]byte{}, magic...)
	msg = append(msg, sFlags)
	msg = append(msg, sPub...)
	msg = append(msg, nonce...)
	if _, err := c.Write(msg); err != nil {
		return 0, nil, err
	}
	buf := make([]byte, 1+1+32+32)
	if _, err := io.ReadFull(c, buf); err != nil {
		return 0, nil, err
	}
	kind, cFlags, cPub, gotMac := buf[0], buf[1], buf[2:34], buf[34:]
	want := hsMac(token, "pol-c", nonce, kind, sFlags, cFlags, sPub, cPub)
	if !hmac.Equal(gotMac, want) || kind < connControl || kind > connMux {
		return 0, nil, errAuth
	}
	if _, err := c.Write(hsMac(token, "pol-s", nonce, kind, sFlags, cFlags, sPub, cPub)); err != nil {
		return 0, nil, err
	}
	conn := c
	if sFlags&encFlag != 0 && cFlags&encFlag != 0 {
		ss, err := sharedSecret(eph, cPub)
		if err != nil {
			return 0, nil, err
		}
		keys, err := deriveKeys(token, ss, false) // server = responder
		if err != nil {
			return 0, nil, err
		}
		conn = newAEADConn(c, keys)
	}
	return kind, conn, nil
}

func clientHandshake(c net.Conn, token string, kind byte, encrypt bool) (net.Conn, error) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	eph, err := genEphemeral()
	if err != nil {
		return nil, err
	}
	hello := make([]byte, 4+1+32+32)
	if _, err := io.ReadFull(c, hello); err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if string(hello[:4]) != string(magic) {
		return nil, errors.New("handshake: not a pol server (version mismatch?)")
	}
	sFlags, sPub, nonce := hello[4], hello[5:37], hello[37:69]
	cFlags := byte(0)
	if encrypt {
		cFlags |= encFlag
	}
	cPub := eph.PublicKey().Bytes()
	out := []byte{kind, cFlags}
	out = append(out, cPub...)
	out = append(out, hsMac(token, "pol-c", nonce, kind, sFlags, cFlags, sPub, cPub)...)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	proof := make([]byte, 32)
	if _, err := io.ReadFull(c, proof); err != nil {
		return nil, fmt.Errorf("handshake rejected (wrong token?): %w", err)
	}
	if !hmac.Equal(proof, hsMac(token, "pol-s", nonce, kind, sFlags, cFlags, sPub, cPub)) {
		return nil, errors.New("handshake: server failed to prove the token")
	}
	conn := c
	if sFlags&encFlag != 0 && cFlags&encFlag != 0 {
		ss, err := sharedSecret(eph, sPub)
		if err != nil {
			return nil, err
		}
		keys, err := deriveKeys(token, ss, true) // client = initiator
		if err != nil {
			return nil, err
		}
		conn = newAEADConn(c, keys)
	}
	return conn, nil
}

// encodeOpen is the open header body (used by both pooled data conns and mux
// SYN frames):  proto[1] | tlen[1] | target | slen[1] | src
// src is the visitor's address (for PROXY protocol); it may be empty.
func encodeOpen(proto byte, target, src string) []byte {
	if len(target) > 255 {
		target = target[:255]
	}
	if len(src) > 255 {
		src = src[:255]
	}
	b := make([]byte, 0, 3+len(target)+len(src))
	b = append(b, proto, byte(len(target)))
	b = append(b, target...)
	b = append(b, byte(len(src)))
	b = append(b, src...)
	return b
}

func decodeOpen(p []byte) (proto byte, target, src string, ok bool) {
	if len(p) < 2 {
		return
	}
	proto = p[0]
	tl := int(p[1])
	if 2+tl+1 > len(p) {
		return
	}
	target = string(p[2 : 2+tl])
	sl := int(p[2+tl])
	if 2+tl+1+sl != len(p) {
		return
	}
	src = string(p[3+tl : 3+tl+sl])
	return proto, target, src, true
}

func writeOpenHeader(w io.Writer, proto byte, target, src string) error {
	_, err := w.Write(encodeOpen(proto, target, src))
	return err
}

// readOpenHeader reads a pooled-conn open header, skipping leading ping bytes.
func readOpenHeader(r io.Reader) (proto byte, target, src string, err error) {
	one := make([]byte, 1)
	for {
		if _, err = io.ReadFull(r, one); err != nil {
			return
		}
		if one[0] != protoPing {
			break
		}
	}
	proto = one[0]
	if proto != protoTCP && proto != protoUDP {
		return 0, "", "", fmt.Errorf("bad proto byte %d", proto)
	}
	readStr := func() (string, error) {
		if _, e := io.ReadFull(r, one); e != nil {
			return "", e
		}
		a := make([]byte, one[0])
		if _, e := io.ReadFull(r, a); e != nil {
			return "", e
		}
		return string(a), nil
	}
	if target, err = readStr(); err != nil {
		return
	}
	if src, err = readStr(); err != nil {
		return
	}
	return proto, target, src, nil
}

// UDP datagrams over a stream: len[2] | payload
func writeDatagram(w io.Writer, p []byte) error {
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b, uint16(len(p)))
	copy(b[2:], p)
	_, err := w.Write(b)
	return err
}

func readDatagram(r io.Reader, buf []byte) (int, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > len(buf) {
		return 0, errors.New("datagram too large")
	}
	_, err := io.ReadFull(r, buf[:n])
	return n, err
}
