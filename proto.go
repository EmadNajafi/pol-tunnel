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

var magic = []byte("POL1")

var errAuth = errors.New("authentication failed")

func mac(token, label string, nonce []byte, kind byte) []byte {
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte(label))
	h.Write(nonce)
	h.Write([]byte{kind})
	return h.Sum(nil)
}

// serverHandshake authenticates an incoming transport connection and returns its kind.
func serverHandshake(c net.Conn, token string) (byte, error) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	if _, err := c.Write(append(append([]byte{}, magic...), nonce...)); err != nil {
		return 0, err
	}
	buf := make([]byte, 33)
	if _, err := io.ReadFull(c, buf); err != nil {
		return 0, err
	}
	kind := buf[0]
	if !hmac.Equal(buf[1:], mac(token, "pol-c", nonce, kind)) || kind < connControl || kind > connMux {
		return 0, errAuth
	}
	if _, err := c.Write(mac(token, "pol-s", nonce, kind)); err != nil {
		return 0, err
	}
	return kind, nil
}

func clientHandshake(c net.Conn, token string, kind byte) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	hello := make([]byte, 36)
	if _, err := io.ReadFull(c, hello); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if string(hello[:4]) != string(magic) {
		return errors.New("handshake: not a pol server")
	}
	nonce := hello[4:]
	if _, err := c.Write(append([]byte{kind}, mac(token, "pol-c", nonce, kind)...)); err != nil {
		return err
	}
	proof := make([]byte, 32)
	if _, err := io.ReadFull(c, proof); err != nil {
		return fmt.Errorf("handshake rejected (wrong token?): %w", err)
	}
	if !hmac.Equal(proof, mac(token, "pol-s", nonce, kind)) {
		return errors.New("handshake: server failed to prove the token")
	}
	return nil
}

func writeOpenHeader(w io.Writer, proto byte, addr string) error {
	if len(addr) > 255 {
		return errors.New("target address too long")
	}
	b := make([]byte, 0, 2+len(addr))
	b = append(b, proto, byte(len(addr)))
	b = append(b, addr...)
	_, err := w.Write(b)
	return err
}

// readOpenHeader reads the open header, skipping ping bytes.
func readOpenHeader(r io.Reader) (proto byte, addr string, err error) {
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
		return 0, "", fmt.Errorf("bad proto byte %d", proto)
	}
	if _, err = io.ReadFull(r, one); err != nil {
		return
	}
	a := make([]byte, one[0])
	if _, err = io.ReadFull(r, a); err != nil {
		return
	}
	return proto, string(a), nil
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
