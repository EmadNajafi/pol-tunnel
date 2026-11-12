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
	wbuf    []byte // reused: one outgoing record (guarded by wmu)
	cbuf    []byte // reused: one incoming record (guarded by rmu)
	pbuf    []byte // reused: its plaintext; readbuf points into it
	expect  uint64 // next record counter we require (anti-replay for the stream)
}

// aeadMaxRecord is the most plaintext one record carries: the sealed record
// (nonce + ciphertext + tag) must fit the uint16 length prefix. A larger value
// silently wraps the length and corrupts the stream (e.g. a 64 KiB mux frame).
const aeadMaxRecord = 0xffff - gcmNonce - gcmTag

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
		// one write per record: len[2] | nonce[12] | ct+tag, sealed straight
		// into a buffer that is reused (wmu is held), not allocated per record
		a.wbuf = a.keys.send.sealAppend(append(a.wbuf[:0], 0, 0), p[:n])
		binary.BigEndian.PutUint16(a.wbuf, uint16(len(a.wbuf)-2))
		if _, err := a.Conn.Write(a.wbuf); err != nil {
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
	return n, nil
}

// readRecord reads and opens one record. The ciphertext and plaintext buffers
// are reused: it is only called once the previous plaintext is used up.
func (a *aeadConn) readRecord() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(a.Conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < gcmNonce+gcmTag {
		return nil, errors.New("aead: bad record length")
	}
	if cap(a.cbuf) < n {
		a.cbuf = make([]byte, 0, 0xffff)
	}
	buf := a.cbuf[:n]
	if _, err := io.ReadFull(a.Conn, buf); err != nil {
		return nil, err
	}
	// enforce strictly increasing record counter (anti-replay / anti-reorder)
	ctr := binary.BigEndian.Uint64(buf[4:gcmNonce])
	if ctr != a.expect {
		return nil, errors.New("aead: record counter out of order (replay?)")
	}
	a.expect++
	plain, err := a.keys.recv.openAppend(a.pbuf[:0], buf)
	if err != nil {
		return nil, err
	}
	a.pbuf = plain
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
