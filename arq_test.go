package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"
)

// lossyLink wires two arqConns together with packet loss and occasional
// reordering. One goroutine per direction (no per-packet timers), so the test's
// wall-clock reflects the ARQ, not timer/goroutine overhead.
type lossyLink struct {
	loss float64
	a, b *arqConn
	chA  chan []byte // packets headed to a
	chB  chan []byte // packets headed to b
}

func (l *lossyLink) pump(ch chan []byte, to *arqConn, seed uint64) {
	rnd := mrand.New(mrand.NewPCG(seed, seed*7+1))
	var held []byte
	for p := range ch {
		if rnd.Float64() < l.loss {
			continue
		}
		if held == nil && rnd.Float64() < 0.15 { // delay one packet to reorder
			held = p
			continue
		}
		to.input(p)
		if held != nil {
			to.input(held)
			held = nil
		}
	}
}

func newLink(loss float64) *lossyLink {
	l := &lossyLink{loss: loss, chA: make(chan []byte, 8192), chB: make(chan []byte, 8192)}
	la := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1)}
	lb := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2)}
	send := func(ch chan []byte) func([]byte) error {
		return func(p []byte) error {
			cp := append([]byte(nil), p...)
			select {
			case ch <- cp:
			default: // link buffer full: drop, like a real congested link
			}
			return nil
		}
	}
	l.a = newARQ(send(l.chB), la, lb) // a's output goes toward b
	l.b = newARQ(send(l.chA), lb, la)
	go l.pump(l.chB, l.b, 1)
	go l.pump(l.chA, l.a, 2)
	return l
}

func TestARQLossy(t *testing.T) {
	for _, loss := range []float64{0, 0.1, 0.3} {
		t.Run(name(loss), func(t *testing.T) {
			link := newLink(loss)
			defer link.a.Close()
			defer link.b.Close()

			size := 3 << 20 // 3 MB each way; lighter under extreme loss
			if loss >= 0.3 {
				size = 1 << 20
			}
			payload := make([]byte, size)
			rand.Read(payload)
			reply := make([]byte, size*2/3)
			rand.Read(reply)

			var wg sync.WaitGroup
			wg.Add(4)
			var gotB, gotA []byte
			var errs [4]error

			go func() {
				defer wg.Done()
				_, errs[0] = io.Copy(writerOnly{link.a}, bytes.NewReader(payload))
				link.a.CloseWrite()
			}()
			go func() {
				defer wg.Done()
				_, errs[1] = io.Copy(writerOnly{link.b}, bytes.NewReader(reply))
				link.b.CloseWrite()
			}()
			go func() { defer wg.Done(); gotB, errs[2] = io.ReadAll(link.b) }()
			go func() { defer wg.Done(); gotA, errs[3] = io.ReadAll(link.a) }()

			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(90 * time.Second):
				t.Fatal("timeout (deadlock or stall)")
			}
			for _, e := range errs {
				if e != nil {
					t.Fatal(e)
				}
			}
			if !bytes.Equal(gotB, payload) {
				t.Errorf("A->B corrupt: got %d want %d bytes", len(gotB), len(payload))
			}
			if !bytes.Equal(gotA, reply) {
				t.Errorf("B->A corrupt: got %d want %d bytes", len(gotA), len(reply))
			}
		})
	}
}

// TestSpoofConns drives the spoof transport (plain-UDP mode) directly, with a
// small configurable number of concurrent streams, to isolate the pooled path.
func TestSpoofConns(t *testing.T) {
	setLogLevel("warn")
	for _, mux := range []bool{true, false} {
		tr := "spoof"
		if mux {
			tr = "spoofmux"
		}
		t.Run(tr, func(t *testing.T) {
			tcpTarget := echoTCP(t)
			tunnelPort, pubTCP := freePort(t), freePort(t)
			common := defaultCommon()
			common.Transport = tr
			common.Token = "tok"
			common.Heartbeat = 2 * time.Second
			sc := &ServerConfig{Common: common, BindAddr: fmt.Sprintf("127.0.0.1:%d", tunnelPort),
				Ports: []string{fmt.Sprintf("127.0.0.1:%d=%s", pubTCP, tcpTarget)}}
			srv, err := NewServer(sc)
			if err != nil {
				t.Fatal(err)
			}
			go srv.Run()
			cc := &ClientConfig{Common: common, RemoteAddr: sc.BindAddr, ConnectionPool: 3, RetryInterval: time.Second}
			go NewClient(cc).Run()
			time.Sleep(1500 * time.Millisecond)

			var wg sync.WaitGroup
			errs := make(chan error, 8)
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", pubTCP))
					if err != nil {
						errs <- err
						return
					}
					defer c.Close()
					data := make([]byte, 256<<10)
					for j := range data {
						data[j] = byte(i)
					}
					go func() { c.Write(data); c.(*net.TCPConn).CloseWrite() }()
					c.SetReadDeadline(time.Now().Add(20 * time.Second))
					got, err := io.ReadAll(c)
					if err != nil {
						errs <- fmt.Errorf("conn %d: %v", i, err)
						return
					}
					if !bytes.Equal(got, data) {
						errs <- fmt.Errorf("conn %d: got %d/%d bytes, mismatch", i, len(got), len(data))
					}
				}(i)
			}
			wg.Wait()
			close(errs)
			for e := range errs {
				t.Error(e)
			}
		})
	}
}

type writerOnly struct{ w io.Writer }

func (w writerOnly) Write(p []byte) (int, error) { return w.w.Write(p) }

func name(f float64) string {
	switch f {
	case 0:
		return "loss0"
	case 0.1:
		return "loss10"
	default:
		return "loss30"
	}
}

// A reader that stops reading must make the sender stop too (bounded
// buffering), and the stream must resume intact once it reads again.
func TestARQSlowReaderBounded(t *testing.T) {
	l := newLink(0)
	defer l.a.Close()
	defer l.b.Close()

	const total = 16 << 20 // far more than the receive window
	msg := make([]byte, total)
	rand.Read(msg)
	go func() { l.a.Write(msg); l.a.CloseWrite() }()

	time.Sleep(1500 * time.Millisecond) // b reads nothing meanwhile
	l.b.mu.Lock()
	backlog := len(l.b.rStream)
	l.b.mu.Unlock()
	if limit := 2 * arqRecvWnd * arqMTU; backlog > limit {
		t.Fatalf("unread backlog %d bytes exceeds %d: receive window ignores unread data", backlog, limit)
	}

	l.b.SetReadDeadline(time.Now().Add(60 * time.Second))
	got, err := io.ReadAll(l.b)
	if err != nil {
		t.Fatalf("read: %v (got %d of %d)", err, len(got), total)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("stream corrupted: got %d bytes", len(got))
	}
}
