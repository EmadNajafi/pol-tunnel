package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Minimal RFC 6455 WebSocket carrying a raw byte stream in binary frames.
// Enough to pass through CDNs / HTTP proxies like Backhaul's ws transports.

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type wsConn struct {
	net.Conn
	br       *bufio.Reader
	isClient bool

	wmu sync.Mutex

	remaining uint64 // bytes left in current frame
	masked    bool
	maskKey   [4]byte
	maskPos   int
	rclosed   bool // peer sent a close frame (its half-close)
	wclosed   bool
}

// CloseWrite sends a close frame; the peer's Read returns EOF but it can still
// send to us. This gives ws the same half-close semantics as TCP.
func (w *wsConn) CloseWrite() error {
	w.wmu.Lock()
	if w.wclosed {
		w.wmu.Unlock()
		return nil
	}
	w.wclosed = true
	w.wmu.Unlock()
	_, err := w.writeFrame(0x8, nil)
	return err
}

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsClientUpgrade performs the HTTP upgrade over an already-dialed conn.
func wsClientUpgrade(c net.Conn, host, path string) (net.Conn, error) {
	kb := make([]byte, 16)
	rand.Read(kb)
	key := base64.StdEncoding.EncodeToString(kb)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, host, key)
	if _, err := io.WriteString(c, req); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("websocket upgrade failed: %s", resp.Status)
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return nil, errors.New("websocket upgrade: bad accept key")
	}
	return &wsConn{Conn: c, br: br, isClient: true}, nil
}

// wsServerHandler upgrades matching requests and hands the conns to out.
// Everything else gets a boring 404 so the port looks like a plain web server.
func wsServerHandler(path string, out chan<- net.Conn) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
			r.Header.Get("Sec-WebSocket-Key") == "" {
			http.NotFound(w, r)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "unsupported", http.StatusInternalServerError)
			return
		}
		c, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + wsAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n\r\n"
		if _, err := io.WriteString(c, resp); err != nil {
			c.Close()
			return
		}
		out <- &wsConn{Conn: c, br: brw.Reader}
	})
}

func (w *wsConn) Read(p []byte) (int, error) {
	for w.remaining == 0 {
		if w.rclosed {
			return 0, io.EOF
		}
		if err := w.nextFrame(); err != nil {
			return 0, err
		}
	}
	if uint64(len(p)) > w.remaining {
		p = p[:w.remaining]
	}
	n, err := w.br.Read(p)
	if w.masked {
		for i := 0; i < n; i++ {
			p[i] ^= w.maskKey[w.maskPos&3]
			w.maskPos++
		}
	}
	w.remaining -= uint64(n)
	return n, err
}

func (w *wsConn) nextFrame() error {
	var h [2]byte
	if _, err := io.ReadFull(w.br, h[:]); err != nil {
		return err
	}
	op := h[0] & 0x0f
	w.masked = h[1]&0x80 != 0
	ln := uint64(h[1] & 0x7f)
	switch ln {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(w.br, b[:]); err != nil {
			return err
		}
		ln = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(w.br, b[:]); err != nil {
			return err
		}
		ln = binary.BigEndian.Uint64(b[:])
	}
	if w.masked {
		if _, err := io.ReadFull(w.br, w.maskKey[:]); err != nil {
			return err
		}
		w.maskPos = 0
	}
	switch op {
	case 0x0, 0x1, 0x2: // continuation / text / binary: stream payload
		w.remaining = ln
		return nil
	case 0x8: // close (payload, if any, is ignored)
		if ln > 125 {
			return errors.New("websocket: control frame too long")
		}
		if _, err := w.br.Discard(int(ln)); err != nil {
			return err
		}
		w.rclosed = true
		return io.EOF
	case 0x9, 0xA: // ping / pong: read payload; answer pings
		if ln > 125 {
			return errors.New("websocket: control frame too long")
		}
		payload := make([]byte, ln)
		if _, err := io.ReadFull(w.br, payload); err != nil {
			return err
		}
		if w.masked {
			for i := range payload {
				payload[i] ^= w.maskKey[i&3]
			}
		}
		if op == 0x9 {
			w.writeFrame(0xA, payload)
		}
		return nil
	default:
		return fmt.Errorf("websocket: unknown opcode %d", op)
	}
}

func (w *wsConn) writeFrame(op byte, p []byte) (int, error) {
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|op)
	maskBit := byte(0)
	if w.isClient {
		maskBit = 0x80
	}
	switch n := len(p); {
	case n < 126:
		hdr = append(hdr, maskBit|byte(n))
	case n <= 0xffff:
		hdr = append(hdr, maskBit|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, maskBit|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	frame := make([]byte, len(hdr), len(hdr)+4+len(p))
	copy(frame, hdr)
	if w.isClient {
		var key [4]byte
		rand.Read(key[:])
		frame = append(frame, key[:]...)
		start := len(frame)
		frame = append(frame, p...)
		for i := range p {
			frame[start+i] ^= key[i&3]
		}
	} else {
		frame = append(frame, p...)
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if _, err := w.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	w.wmu.Lock()
	closed := w.wclosed
	w.wmu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 64*1024 {
			n = 64 * 1024
		}
		if _, err := w.writeFrame(0x2, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
