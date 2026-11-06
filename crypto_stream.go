package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// aeadConn wraps a reliable, ordered net.Conn (tcp/ws/wss/arq) in an encrypted
// framing: each Write becomes one AEAD-sealed, length-prefixed record.
//
//	len[2] | nonce[12] | ciphertext+tag
//
// The underlying transport is ordered and lossless, so the receiver enforces a
// strictly increasing record counter (built into the nonce) — any replay,
// reorder or truncation of records fails the AEAD and drops the connection.
type aeadConn struct {
	net.Conn
	keys *directKeys

	wmu sync.Mutex

	rmu     sync.Mutex
	readbuf []byte // leftover plaintext from a partial Read
	expect  uint64 // next record counter we require (anti-replay for the stream)
}

const aeadMaxRecord = 64 * 1024

func newAEADConn(c net.Conn, keys *directKeys) *aeadConn {
	return &aeadConn{Conn: c, keys: keys, expect: 1}
}

func (a *aeadConn) Write(p []byte) (int, error) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > aeadMaxRecord {
			n = aeadMaxRecord
		}
		sealed := a.keys.send.seal(p[:n]) // nonce[12] | ct+tag
		// one write per record: len[2] | sealed (avoids a tiny separate packet)
		rec := make([]byte, 2+len(sealed))
		binary.BigEndian.PutUint16(rec, uint16(len(sealed)))
		copy(rec[2:], sealed)
		if _, err := a.Conn.Write(rec); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (a *aeadConn) Read(p []byte) (int, error) {
	a.rmu.Lock()
	defer a.rmu.Unlock()
	if len(a.readbuf) == 0 {
		plain, err := a.readRecord()
		if err != nil {
			return 0, err
		}
		a.readbuf = plain
	}
	n := copy(p, a.readbuf)
	a.readbuf = a.readbuf[n:]
	if len(a.readbuf) == 0 {
		a.readbuf = nil
	}
	return n, nil
}

func (a *aeadConn) readRecord() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(a.Conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < gcmNonce+gcmTag || n > aeadMaxRecord+gcmNonce+gcmTag {
		return nil, errors.New("aead: bad record length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(a.Conn, buf); err != nil {
		return nil, err
	}
	// enforce strictly increasing record counter (anti-replay / anti-reorder)
	ctr := binary.BigEndian.Uint64(buf[4:gcmNonce])
	if ctr != a.expect {
		return nil, errors.New("aead: record counter out of order (replay?)")
	}
	a.expect++
	plain, err := a.keys.recv.open(buf)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// CloseWrite preserves half-close when the underlying conn supports it.
func (a *aeadConn) CloseWrite() error {
	if cw, ok := a.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (a *aeadConn) SetDeadline(t time.Time) error      { return a.Conn.SetDeadline(t) }
func (a *aeadConn) SetReadDeadline(t time.Time) error  { return a.Conn.SetReadDeadline(t) }
func (a *aeadConn) SetWriteDeadline(t time.Time) error { return a.Conn.SetWriteDeadline(t) }
