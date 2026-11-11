package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func loadCfgString(t *testing.T, body string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(p)
}

func TestPerformanceProfileConfig(t *testing.T) {
	srv := "[server]\ntoken = \"t\"\nports = [\"443\"]\n"
	cli := "[client]\ntoken = \"t\"\nremote_addr = \"1.2.3.4:1\"\n"

	// no key: exactly the values pol always had
	c, err := loadCfgString(t, srv)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.MuxWindow != 512*1024 || c.Server.MuxFrameSize != 32*1024 || !c.Server.Nodelay || c.Server.ChannelSize != 2048 {
		t.Errorf("no profile changed the defaults: %+v", c.Server.Common)
	}
	c, _ = loadCfgString(t, cli)
	if c.Client.ConnectionPool != 8 {
		t.Errorf("default connection_pool = %d, want 8", c.Client.ConnectionPool)
	}

	for name, p := range perfProfiles {
		c, err := loadCfgString(t, srv+"performance = \""+name+"\"\n")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Server.MuxWindow != p.MuxWindow || c.Server.MuxFrameSize != p.MuxFrameSize || c.Server.Nodelay != p.Nodelay {
			t.Errorf("%s: server got window=%d frame=%d nodelay=%v", name, c.Server.MuxWindow, c.Server.MuxFrameSize, c.Server.Nodelay)
		}
		c, err = loadCfgString(t, cli+"performance = \""+name+"\"\n")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Client.ConnectionPool != p.Pool {
			t.Errorf("%s: connection_pool = %d, want %d", name, c.Client.ConnectionPool, p.Pool)
		}
	}

	// an explicit key wins over the profile
	c, err = loadCfgString(t, cli+"performance = \"aggressive\"\nmux_window = 1048576\nconnection_pool = 3\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Client.MuxWindow != 1048576 || c.Client.ConnectionPool != 3 {
		t.Errorf("explicit keys lost to the profile: window=%d pool=%d", c.Client.MuxWindow, c.Client.ConnectionPool)
	}

	if _, err := loadCfgString(t, srv+"performance = \"ludicrous\"\n"); err == nil {
		t.Error("an unknown profile name was accepted")
	}
}

// Every profile's ARQ tuning must still deliver a lossy, reordered stream
// intact in both directions.
func TestARQProfilesLossy(t *testing.T) {
	defer applyARQProfile("balance")
	for name := range perfProfiles {
		t.Run(name, func(t *testing.T) {
			applyARQProfile(name)
			link := newLink(0.1)
			defer link.a.Close()
			defer link.b.Close()
			payload := make([]byte, 2<<20)
			rand.Read(payload)
			reply := make([]byte, 1<<20)
			rand.Read(reply)

			var wg sync.WaitGroup
			wg.Add(4)
			var gotA, gotB []byte
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
			if !bytes.Equal(gotB, payload) || !bytes.Equal(gotA, reply) {
				t.Fatalf("stream corrupted: got %d/%d bytes, want %d/%d", len(gotB), len(gotA), len(payload), len(reply))
			}
		})
	}
}

// ---- a pipe with one-way delay and unlimited bandwidth ----

type delayedChunk struct {
	at   time.Time
	data []byte
}

type delayQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	q      []delayedChunk
	closed bool
}

func newDelayQueue() *delayQueue {
	d := &delayQueue{}
	d.cond = sync.NewCond(&d.mu)
	return d
}

type delayConn struct {
	in, out *delayQueue
	delay   time.Duration
}

func delayPipe(d time.Duration) (net.Conn, net.Conn) {
	x, y := newDelayQueue(), newDelayQueue()
	return &delayConn{in: x, out: y, delay: d}, &delayConn{in: y, out: x, delay: d}
}

func (c *delayConn) Write(p []byte) (int, error) {
	c.out.mu.Lock()
	defer c.out.mu.Unlock()
	if c.out.closed {
		return 0, io.ErrClosedPipe
	}
	c.out.q = append(c.out.q, delayedChunk{time.Now().Add(c.delay), append([]byte(nil), p...)})
	c.out.cond.Broadcast()
	return len(p), nil
}

func (c *delayConn) Read(p []byte) (int, error) {
	c.in.mu.Lock()
	for len(c.in.q) == 0 && !c.in.closed {
		c.in.cond.Wait()
	}
	if len(c.in.q) == 0 {
		c.in.mu.Unlock()
		return 0, io.EOF
	}
	at := c.in.q[0].at
	c.in.mu.Unlock()
	time.Sleep(time.Until(at))
	c.in.mu.Lock()
	defer c.in.mu.Unlock()
	if len(c.in.q) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.in.q[0].data)
	if n == len(c.in.q[0].data) {
		c.in.q = c.in.q[1:]
	} else {
		c.in.q[0].data = c.in.q[0].data[n:]
	}
	return n, nil
}

func (c *delayConn) Close() error {
	for _, q := range []*delayQueue{c.in, c.out} {
		q.mu.Lock()
		q.closed = true
		q.q = nil
		q.cond.Broadcast()
		q.mu.Unlock()
	}
	return nil
}
func (c *delayConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *delayConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *delayConn) SetDeadline(time.Time) error      { return nil }
func (c *delayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *delayConn) SetWriteDeadline(time.Time) error { return nil }

// muxRate measures what one mux stream carries in `dur` over a path with the
// given one-way delay, for a profile's window and frame size.
func muxRate(t *testing.T, p perfProfile, oneWay, dur time.Duration) float64 {
	a, b := delayPipe(oneWay)
	hb := 5 * time.Second
	sender := NewSession(a, p.MuxFrameSize, p.MuxWindow, hb)
	recver := NewSession(b, p.MuxFrameSize, p.MuxWindow, hb)
	defer sender.Close()
	defer recver.Close()

	var got int64
	var mu sync.Mutex
	go func() {
		st, err := recver.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 64<<10)
		for {
			n, err := st.Read(buf)
			mu.Lock()
			got += int64(n)
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	st, err := sender.Open(protoTCP, "x:1", "")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 32<<10)
		for {
			if _, err := st.Write(buf); err != nil {
				return
			}
		}
	}()
	time.Sleep(4 * oneWay) // let the window grants settle
	mu.Lock()
	start := got
	mu.Unlock()
	time.Sleep(dur)
	mu.Lock()
	n := got - start
	mu.Unlock()
	return float64(n) * 8 / dur.Seconds() / 1e6 // Mbit/s
}

// On a path with real latency one mux stream is paced by window / round trip,
// so the larger windows of turbo and above must carry clearly more than
// balance does.
func TestPerformanceProfilesMuxRate(t *testing.T) {
	const oneWay = 40 * time.Millisecond // an 80 ms round trip, like Iran <-> Europe
	rates := map[string]float64{}
	for _, name := range []string{"balance", "turbo", "aggressive", "throughput"} {
		rates[name] = muxRate(t, perfProfiles[name], oneWay, 1500*time.Millisecond)
		t.Logf("%-10s window %5d KiB: %7.1f Mbit/s per stream at 80 ms RTT", name, perfProfiles[name].MuxWindow/1024, rates[name])
	}
	// (kept loose: under the race detector the CPU, not the window, caps the top rates)
	if rates["turbo"] < 1.5*rates["balance"] {
		t.Errorf("turbo (%.1f Mbit/s) should carry clearly more than balance (%.1f Mbit/s)", rates["turbo"], rates["balance"])
	}
}

// The whole tunnel (handshake, mux, UDP forwarding) over the ARQ transport
// must work with every profile's tuning, encrypted.
func TestPerformanceProfilesEndToEndSpoof(t *testing.T) {
	setLogLevel("warn")
	defer applyARQProfile("balance")
	for _, name := range []string{"turbo", "aggressive", "throughput"} {
		t.Run(name, func(t *testing.T) {
			applyARQProfile(name)
			runE2E(t, "spoofmux", true)
		})
	}
}
