package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDev is an in-memory l3Device: packets written to in are "read from the
// TUN", packets the engine writes land in out.
type fakeDev struct {
	in     chan []byte
	out    chan []byte
	mu     sync.Mutex
	mtus   []int
	closed chan struct{}
	once   sync.Once
}

func newFakeDev() *fakeDev {
	return &fakeDev{in: make(chan []byte, 256), out: make(chan []byte, 256), closed: make(chan struct{})}
}

func (d *fakeDev) Read(p []byte) (int, error) {
	select {
	case b := <-d.in:
		return copy(p, b), nil
	case <-d.closed:
		return 0, errors.New("closed")
	}
}
func (d *fakeDev) Write(p []byte) (int, error) {
	d.out <- append([]byte(nil), p...)
	return len(p), nil
}
func (d *fakeDev) setMTU(m int) error {
	d.mu.Lock()
	d.mtus = append(d.mtus, m)
	d.mu.Unlock()
	return nil
}
func (d *fakeDev) lastMTU() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.mtus) == 0 {
		return 0
	}
	return d.mtus[len(d.mtus)-1]
}
func (d *fakeDev) close() { d.once.Do(func() { close(d.closed) }) }

// ipv4UDP builds a minimal IPv4/UDP packet (checksums are not checked by the engine).
func ipv4UDP(src, dst string, sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, 17
	copy(b[12:16], net.ParseIP(src).To4())
	copy(b[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func TestFlowPath(t *testing.T) {
	const n = 4
	a := ipv4UDP("10.0.0.1", "10.0.0.2", 40000, 443, []byte("x"))
	b := ipv4UDP("10.0.0.1", "10.0.0.2", 40000, 443, []byte("other payload"))
	if flowPath(a, n) != flowPath(b, n) {
		t.Error("same flow mapped to different paths")
	}
	used := map[int]bool{}
	for p := 0; p < 64; p++ {
		used[flowPath(ipv4UDP("10.0.0.1", "10.0.0.2", uint16(40000+p), 443, nil), n)] = true
	}
	if len(used) != n {
		t.Errorf("64 flows used %d of %d paths", len(used), n)
	}
	if flowPath(a, 1) != 0 || flowPath([]byte{0x00, 1, 2}, n) != 0 || flowPath(make([]byte, 40), n) != 0 {
		t.Error("single path / non-IP input must map to path 0")
	}
	for i := 0; i < 32; i++ { // garbage never panics or leaves the range
		g := bytes.Repeat([]byte{byte(0x40 + i)}, 20+i)
		if p := flowPath(g, n); p < 0 || p >= n {
			t.Fatalf("path %d out of range", p)
		}
	}
	// fragments of one datagram stay together
	f1 := ipv4UDP("10.0.0.1", "10.0.0.2", 1, 2, nil)
	f2 := ipv4UDP("10.0.0.1", "10.0.0.2", 9, 9, nil)
	binary.BigEndian.PutUint16(f1[6:], 0x2000) // MF
	binary.BigEndian.PutUint16(f2[6:], 0x0010) // offset
	if flowPath(f1, n) != flowPath(f2, n) {
		t.Error("fragments of one datagram split across paths")
	}
}

// dropBig is a sender that drops datagrams larger than limit (a route with a
// small MTU) and counts packets per path.
type dropBig struct {
	inner packetSender
	limit int
	sent  atomic.Int64
}

func (d *dropBig) sendTo(b []byte, dst *net.UDPAddr) error {
	d.sent.Add(1)
	if d.limit > 0 && len(b) > d.limit {
		return nil
	}
	return d.inner.sendTo(b, dst)
}
func (d *dropBig) Close() error { return d.inner.Close() }

// startPair runs a server and a client engine over n loopback paths.
func startPair(t *testing.T, n int, autoMTU bool) (srv, cli *directEngine, sdev, cdev *fakeDev) {
	t.Helper()
	listen := func() *net.UDPConn {
		s, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	var ssocks, csocks []*net.UDPConn
	cpeers := make([]*net.UDPAddr, n)
	for i := 0; i < n; i++ {
		ssocks = append(ssocks, listen())
		csocks = append(csocks, listen())
		cpeers[i] = ssocks[i].LocalAddr().(*net.UDPAddr)
	}
	sdev, cdev = newFakeDev(), newFakeDev()
	var err error
	srv, err = newDirectEngine(&DirectConfig{Role: "server", Token: "tok", Paths: n, MTU: 1400, AutoMTU: autoMTU}, sdev, ssocks, make([]*net.UDPAddr, n))
	if err != nil {
		t.Fatal(err)
	}
	cli, err = newDirectEngine(&DirectConfig{Role: "client", Token: "tok", Paths: n, MTU: 1400, AutoMTU: autoMTU}, cdev, csocks, cpeers)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*directEngine{srv, cli} {
		for _, p := range e.paths {
			p.sender = &dropBig{inner: p.sender}
		}
	}
	t.Cleanup(func() {
		sdev.close()
		cdev.close()
		srv.close()
		cli.close()
	})
	return
}

func waitFor(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestDirectMultipathEndToEnd(t *testing.T) {
	const n = 3
	srv, cli, sdev, cdev := startPair(t, n, false)
	go srv.run()
	go cli.run()

	waitFor(t, "handshake + every path learned", 5*time.Second, func() bool {
		srv.mu.RLock()
		defer srv.mu.RUnlock()
		for _, p := range srv.peers {
			if p == nil {
				return false
			}
		}
		return srv.up && cli.isUp()
	})

	// many flows client -> server, then answers server -> client
	const flows = 48
	for i := 0; i < flows; i++ {
		cdev.in <- ipv4UDP("10.200.0.2", "10.200.0.1", uint16(30000+i), 443, []byte{byte(i)})
	}
	got := map[byte]bool{}
	for len(got) < flows {
		select {
		case p := <-sdev.out:
			got[p[28]] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("server got %d of %d packets", len(got), flows)
		}
	}
	for i := 0; i < flows; i++ {
		sdev.in <- ipv4UDP("10.200.0.1", "10.200.0.2", 443, uint16(30000+i), []byte{byte(i)})
	}
	for i := 0; i < flows; i++ {
		select {
		case <-cdev.out:
		case <-time.After(3 * time.Second):
			t.Fatalf("client got %d of %d packets", i, flows)
		}
	}
	// traffic really used every path in both directions
	for _, e := range []*directEngine{srv, cli} {
		for _, p := range e.paths {
			if c := p.sender.(*dropBig).sent.Load(); c < 2 {
				t.Errorf("%s path %d sent only %d packets", e.cfg.Role, p.idx, c)
			}
		}
	}
}

func TestDirectAutoMTU(t *testing.T) {
	oldT, oldTries := directProbeTimeout, directProbeTries
	directProbeTimeout, directProbeTries = 150*time.Millisecond, 2
	t.Cleanup(func() { directProbeTimeout, directProbeTries = oldT, oldTries })

	srv, cli, sdev, cdev := startPair(t, 1, true)
	// the client's route drops datagrams over 1300 bytes
	cli.paths[0].sender.(*dropBig).limit = 1300
	go srv.run()
	go cli.run()

	waitFor(t, "client auto MTU", 20*time.Second, func() bool { return cdev.lastMTU() != 0 })
	if got, want := cdev.lastMTU(), 1300-directOverhead; got != want {
		t.Errorf("client mtu = %d, want %d", got, want)
	}
	waitFor(t, "server auto MTU", 20*time.Second, func() bool { return sdev.lastMTU() != 0 })
	if got, want := sdev.lastMTU(), mtuProbeMax-directOverhead; got != want {
		t.Errorf("server mtu = %d, want %d", got, want)
	}
	// probes and acks never reach the device as IP packets
	select {
	case p := <-sdev.out:
		t.Errorf("control message leaked to the device: % x", p[:8])
	case p := <-cdev.out:
		t.Errorf("control message leaked to the device: % x", p[:8])
	default:
	}
}

func TestDirectAutoMTUOldPeer(t *testing.T) {
	oldT := directProbeTimeout
	directProbeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { directProbeTimeout = oldT })
	e := newTestDirect(t, "client")
	e.dev = newFakeDev()
	// nobody acknowledges: up, but the peer is silent
	e.peers[0] = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	e.keys, _ = deriveKeys("tok", make([]byte, 32), true)
	e.up = true
	if got := e.measureMTU(); got != 0 {
		t.Errorf("measureMTU with a silent peer = %d, want 0", got)
	}
}

func TestDirectSpoofPeerReply(t *testing.T) {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()
	e, err := newDirectEngine(&DirectConfig{Role: "server", Token: "tok", SpoofPeerIP: "198.51.100.7"}, nil, []*net.UDPConn{sock}, make([]*net.UDPAddr, 1))
	if err != nil {
		t.Fatal(err)
	}
	got := e.replyAddr(&net.UDPAddr{IP: net.IPv4(10, 10, 10, 10), Port: 5555})
	if got.String() != "198.51.100.7:5555" {
		t.Errorf("reply to forged source went to %v, want 198.51.100.7:5555", got)
	}
	if _, err := newDirectEngine(&DirectConfig{Role: "server", SpoofPeerIP: "nope"}, nil, nil, nil); err == nil {
		t.Error("bad spoof_peer_ip accepted")
	}
}

func TestDirectConfigCarriers(t *testing.T) {
	base := "[direct]\nrole = \"server\"\ntoken = \"t\"\nlocal_ip = \"10.0.0.1\"\npeer_ip = \"10.0.0.2\"\n"
	load := func(extra string) (*Config, error) {
		p := filepath.Join(t.TempDir(), "c.toml")
		os.WriteFile(p, []byte(base+extra), 0o600)
		return LoadConfig(p)
	}
	c, err := load("")
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Direct; d.Carrier != "udp" || d.Paths != 1 || !d.AutoMTU {
		t.Errorf("defaults: carrier=%q paths=%d auto_mtu=%v", d.Carrier, d.Paths, d.AutoMTU)
	}
	c, err = load("carrier = \"spoof\"\nspoof_source = \"10.10.10.10\"\npaths = 4\nauto_mtu = false\nspoof_peer_ip = \"1.2.3.4\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Direct; d.Carrier != "spoof" || d.Paths != 4 || d.AutoMTU || d.SpoofSource != "10.10.10.10" || d.SpoofPeerIP != "1.2.3.4" {
		t.Errorf("parsed %+v", d)
	}
	bad := map[string]string{
		"carrier = \"spoof\"\n":                      "spoof_source",
		"spoof_source = \"10.10.10.10\"\n":           "carrier",
		"carrier = \"tcp\"\n":                        "refused",
		"carrier = \"pigeon\"\n":                     "carrier",
		"paths = 0\n":                                "paths",
		"paths = 17\n":                               "paths",
		"spoof_peer_ip = \"x\"\n":                    "spoof_peer_ip",
		"bind_addr = \"0.0.0.0:65535\"\npaths = 2\n": "65535",
		"mtu = 100\n":                                "mtu",
	}
	for extra, want := range bad {
		if _, err := load(extra); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want it to mention %q", extra, err, want)
		}
	}
}
